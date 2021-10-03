package lokallykke.security

import scala.util.Random

object StateValueGenerator {

  def generateNonce = Random.alphanumeric.take(20).mkString

  def stateFrom(prod : Product) : String = {
    var currentState = System.currentTimeMillis().hashCode().toLong
    prod.productIterator.toList.foreach {
      case el => {
        currentState = (currentState + el.hashCode().toLong) % Long.MaxValue
      }
    }
    val rand = new Random(currentState)
    rand.alphanumeric.take(32).mkString
  }



}
