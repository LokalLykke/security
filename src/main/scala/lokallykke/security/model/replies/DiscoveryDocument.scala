package lokallykke.security.model.replies

import play.api.libs.functional.syntax.toFunctionalBuilderOps
import play.api.libs.json.{JsPath, Reads}

case class DiscoveryDocument(
                            issuer : String,
                            authorizationEndpoint : String,
                            deviceAuthorizationEndpoint : String,
                            tokenEndpoint : String
                            )


object DiscoveryDocument {
  implicit val reads : Reads[DiscoveryDocument] = (
    (JsPath \ "issuer").read[String] and
      (JsPath \ "authorization_endpoint").read[String] and
      (JsPath \ "device_authorization_endpoint").read[String] and
      (JsPath \ "token_endpoint").read[String]
  )(DiscoveryDocument.apply _)
}