package lokallykke.security

import lokallykke.security.GoogleAuthenticator.{AuthenticationReply, DiscoveryDocumentUri, ExchangeTokenBody, ExchangedToken}
import lokallykke.security.model.replies.DiscoveryDocument
import org.slf4j.LoggerFactory
import play.api.libs.json.{JsError, JsSuccess, Json}
import play.api.libs.ws.WSClient

import java.net.URLEncoder
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

class GoogleAuthenticator(client : WSClient) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  def initializationURL(clientId : String, redirectUrl : String, nonce : String, state : String)(implicit executionContext: ExecutionContext) = {
    GoogleAuthenticator.readDiscoveryDocument(client).map {
      case doc => {
        val scope = encodeUrlParameter("openid email")
        val responseType = "code"
        val stateParameter = URLEncoder.encode(state, "UTF-8")
        val nonceParameter = URLEncoder.encode(state, "UTF-8")
        val url = s"""${doc.authorizationEndpoint}?response_type=$responseType&client_id=$clientId&scope=$scope&redirect_uri=$redirectUrl&state=$stateParameter&nonce=$nonceParameter"""
        url
      }
    }

  }

  def exchangeCode(code : String, clientId : String, clientSecret : String, redirectUrl : String)(implicit executionContext: ExecutionContext) = {
    GoogleAuthenticator.readDiscoveryDocument(client).map {
      case doc => {
        val enc = (str : String) =>  URLEncoder.encode(str, "UTF-8")
        //val parameterString = s"code=${enc(code)}&client_id=${enc(clientId)}&client_secret=${enc(clientSecret)}&redirect_uri=$redirectUrl"
        implicit val writes = GoogleAuthenticator.exchangeTokenBodyWrites
        val body = Json.stringify(Json.toJson(ExchangeTokenBody(code, clientId, clientSecret, redirectUrl)))
        client.url(doc.tokenEndpoint).post(body).map{
          case res => {
            logger.info(s"body result: ${res.body}")
            val js = Json.parse(res.body)
            val accessToken = (js \ "access_token").as[String]
            val expiresIn = (js \ "expires_in").as[Long]
            val idToken = (js\"id_token").as[String]
            val scope = (js \ "scope").as[String]
            logger.info(s"Got exchange code callback. accessToken: $accessToken, expiresIn: $expiresIn, idToken: $idToken, scope: $scope")
            ExchangedToken(accessToken,expiresIn,idToken,scope)
          }
        }
      }
    }
  }


  private[GoogleAuthenticator] def loadAuthorizationEndpoint(implicit executionContext: ExecutionContext) = tried(
    client.url(DiscoveryDocumentUri).get().map {
      case res => res.status match {
        case stat if stat > 350 => Left(s"Error in getting authorization endpoint: ${res.statusText}")
        case _ => {
          Json.parse(res.body).validate[DiscoveryDocument] match {
            case JsError(errors) => Left(errors.mkString(", "))
            case JsSuccess(value, path) => Right(value)
          }
        }
      }
    }
  )

  private def encodeUrlParameter(str : String) = URLEncoder.encode(str, "utf-8")


  private def tried[A](act : => Future[Either[String,A]])(implicit executionContext : ExecutionContext) : Future[Either[String, A]] = Try {
    act
  } match {
    case Failure(exc) => Future(Left(exc.getMessage))
    case Success(value) => value
  }


}

object GoogleAuthenticator {
  private val logger = LoggerFactory.getLogger(this.getClass)

  case class AuthenticationReply(body : String, nonce : String, state : String)
  case class ExchangedToken(accessToken : String, expiresInSeconds : Long, idToken : String, scope : String)
  protected[GoogleAuthenticator] case class ExchangeTokenBody(code : String, client_id : String, client_secret : String, redirect_uri : String, grant_type : String = "authorization_code")
  protected implicit val exchangeTokenBodyWrites = Json.writes[ExchangeTokenBody]


  val DiscoveryDocumentUri = """https://accounts.google.com/.well-known/openid-configuration"""


  def readDiscoveryDocument(implicit client : WSClient) = (discoveryDocument, authorizationEndpointUpdateTime) match {
    case (Some(_), updt) if System.currentTimeMillis > updt + (authorizationEndpointDurationInHours.toLong * 1000L) => {
      refreshAuthorizationEndpoint
      discoveryDocument
    }
    case (None, _) => {
      refreshAuthorizationEndpoint
      discoveryDocument
    }
    case (Some(ep),_) => discoveryDocument
  }

  private def refreshAuthorizationEndpoint(implicit client : WSClient) : Unit = {
    implicit val ec = ExecutionContext.global
    val auther = new GoogleAuthenticator(client)
    Await.result(auther.loadAuthorizationEndpoint, 30.seconds) match {
      case Left(err) => {
        logger.error(s"Error while fetching google authorization endpoint")
        discoveryDocument = None
      }
      case Right(doc) => {
        discoveryDocument = Some(doc)
      }
    }
    authorizationEndpointUpdateTime = System.currentTimeMillis
  }

  private var authorizationEndpointDurationInHours = 24
  private var authorizationEndpointUpdateTime = 0L
  private var discoveryDocument : Option[DiscoveryDocument] = None
  def updateAuthorizationEndpointDuration(numberOfHours : Int) : Unit = authorizationEndpointDurationInHours = numberOfHours

}
