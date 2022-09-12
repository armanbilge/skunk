// Copyright (c) 2018-2021 by Rob Norris
// This software is licensed under the MIT License (MIT).
// For more information see LICENSE or https://opensource.org/licenses/MIT

package skunk.net

import cats._
import cats.effect._
import cats.syntax.all._
import fs2.Chunk
import fs2.io.net.Socket
import fs2.io.net.tls.TLSContext
import fs2.io.net.tls.TLSParameters
import fs2.io.net.tls.TLSLogger

object SSLNegotiation {

  /** Parameters for `negotiateSSL`. */
  case class Options[F[_]](
    tlsContext:    TLSContext[F],
    tlsParameters: TLSParameters,
    fallbackOk:    Boolean,
    logger:        Option[String => F[Unit]],
  )

  // SSLRequest message, as a Chunk[Byte]
  val SSLRequest: Chunk[Byte] =
    Chunk.array(Array[Byte](0, 0, 0, 8, 4, -46, 22, 47))

  /**
   * Negotiate SSL with Postgres, given a brand new connected `Socket` and a `TLSContext`. If SSL is
   * unavailable, fall back to the unencrypted socket if `fallbackOk`, otherwise raise an exception.
   */
  def negotiateSSL[F[_]](
    socket:       Socket[F],
    sslOptions:   SSLNegotiation.Options[F]
  )(
    implicit ev: MonadError[F, Throwable]
  ): Resource[F, Socket[F]] = {

    def fail[A](msg: String): F[A] =
      ev.raiseError(new Exception(s"Fatal failure during SSL negotiation: $msg"))

    val initiate: F[Byte] =
      socket.write(SSLRequest) *>
      socket.read(1).map(_.flatMap(_.get(0))).flatMap {
        case None    => fail(s"EOF before 1 byte could be read.")
        case Some(b) => b.pure[F]
      }

    def frintln(s: String): F[Unit] =
      ev.unit.flatMap(_ => ev.pure(println(s)))

    val loggedSocket: Socket[F] = new Socket[F] {
      def endOfInput: F[Unit] = ???
      def endOfOutput: F[Unit] = ???
      def isOpen: F[Boolean] = ???
      def localAddress: F[com.comcast.ip4s.SocketAddress[com.comcast.ip4s.IpAddress]] = ???
      def read(maxBytes: Int): F[Option[fs2.Chunk[Byte]]] =
        frintln(s"underlying reading up to ${maxBytes}") *> socket.read(maxBytes).flatTap(x => frintln(s"underlying read ${x.map(_.size)}"))
      def readN(numBytes: Int): F[fs2.Chunk[Byte]] =
        frintln(s"underlying reading ${numBytes}") *> socket.readN(numBytes) <* frintln(s"underlying read exactly ${numBytes}")
      def reads: fs2.Stream[F,Byte] = ???
      def remoteAddress: F[com.comcast.ip4s.SocketAddress[com.comcast.ip4s.IpAddress]] = ???
      def write(bytes: fs2.Chunk[Byte]): F[Unit] =
        frintln("underlying writing") *> socket.write(bytes) <* frintln("underlying wrote")
      def writes: fs2.Pipe[F,Byte,Nothing] = ???
    }

    Resource.eval(initiate).flatMap {
      case 'S' => 
        Resource.pure[F, Unit](println("here!")) *> sslOptions.tlsContext.clientBuilder(loggedSocket).withParameters(sslOptions.tlsParameters).withLogger(
          sslOptions.logger.fold[TLSLogger[F]](TLSLogger.Disabled)(logger => TLSLogger.Enabled(x => logger(x)))
        ).build.evalTap(_ => println("here?").pure)
      case 'N' => if (sslOptions.fallbackOk) socket.pure[Resource[F, *]] else Resource.eval(fail(s"SSL not available."))
      case  c  => Resource.eval(fail(s"SSL negotiation returned '$c', expected 'S' or 'N'."))
    }

  }


}
