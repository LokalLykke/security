package lokallykke.security

import lokallykke.security.GoogleAuthenticator.{AuthenticationReply, DiscoveryDocumentUri}
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

  def initializeFlow(clientId : String, redirectUrl : String, nonce : String, state : String)(implicit executionContext: ExecutionContext) = {
    GoogleAuthenticator.discoveryDocument(client).map {
      case doc => {
        val scope = encodeUrlParameter("openid email")
        val responseType = "code"

        val url = s"""${doc.authorizationEndpoint}?response_type=$responseType&client_id=$clientId&scope=$scope&redirect_uri=$redirectUrl&state=$state&nonce=$nonce"""
        client.url(url).get().map {
          case res => {
            AuthenticationReply(res.body, nonce, state)
          }
        }
      }
    }
  }

  def exchangeCode(code : String, clientId : String, clientSecret : String, redirectUrl : String)(implicit executionContext: ExecutionContext) = {
    GoogleAuthenticator.discoveryDocument.map {
      case doc => {
        val parameterString = s"code=$code&client_id=$clientId&client_secret=$clientSecret&redirect_uri=$redirectUrl"
        client.url(doc.tokenEndpoint).post(parameterString).map{
          case res => res.body
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

  val DiscoveryDocumentUri = """https://accounts.google.com/.well-known/openid-configuration"""


  def discoveryDocument(implicit client : WSClient) = (discoveryDocument, authorizationEndpointUpdateTime) match {
    case (Some(_), updt) if System.currentTimeMillis > updt + (authorizationEndpointDurationInHours * 1000L) => {
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
