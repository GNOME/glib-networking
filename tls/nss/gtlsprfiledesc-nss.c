/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2010 Red Hat, Inc
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <stdio.h>

#include "config.h"
#include "glib.h"

#include <ssl.h>

#include "gtlsprfiledesc-nss.h"

/* This is a minimal PRFileDesc implementation that reads from and
 * writes to a GIOStream. It only implements the functionality needed
 * for GTlsConnectionNss's use of the NSS SSL APIs.
 */

typedef struct {
  GTlsConnectionBase *tls;

  int record_length, header_length;
  guint8 header[5];
  gboolean shutdown;
} GTlsPRFileDescPrivate;

#define TLS_RECORD_IS_HANDSHAKE(header) ((header)[0] == 22)
#define TLS_RECORD_LENGTH(header) (((header)[3] << 8) + (header)[4])

static PRStatus
g_tls_prfiledesc_get_peer_name (PRFileDesc *fd,
				PRNetAddr  *addr)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;
  GSocketConnection *conn;
  GSocketAddress *remote_addr;
  GInetSocketAddress *isaddr;
  GInetAddress *iaddr;
  guint port;
  GSocketFamily family;

  /* Called first to see if @fd is connected (which it always is)
   * and then later to get the remote IP address to use in the
   * session cache ID.
   */

  if (!G_IS_SOCKET_CONNECTION (priv->tls->base_io_stream))
    goto fail;

  conn = G_SOCKET_CONNECTION (priv->tls->base_io_stream);
  remote_addr = g_socket_connection_get_remote_address (conn, NULL);
  if (!G_IS_INET_SOCKET_ADDRESS (remote_addr))
    goto fail;

  isaddr = G_INET_SOCKET_ADDRESS (remote_addr);
  iaddr = g_inet_socket_address_get_address (isaddr);
  port = g_inet_socket_address_get_port (isaddr);
  family = g_inet_address_get_family (iaddr);

  if (family == G_SOCKET_FAMILY_IPV4)
    {
      addr->inet.family = family;
      addr->inet.port = port;
      memcpy (&addr->inet.ip, g_inet_address_to_bytes (iaddr), 4);
    }
  else if (family == G_SOCKET_FAMILY_IPV6)
    {
      addr->ipv6.family = family;
      addr->ipv6.port = port;
      memcpy (&addr->ipv6.ip, g_inet_address_to_bytes (iaddr), 16);
    }
  else
    {
    fail:
      /* NSS will error out completely if we don't return an IPv4 or
       * IPv6 address. But it doesn't need it for anything other than
       * the session cache keys, so as long as we tell it to not
       * use the cache, it doesn't matter what we return.
       */
      SSL_OptionSet (fd->higher, SSL_NO_CACHE, PR_TRUE);

      addr->inet.family = AF_INET;
      addr->inet.port = 0;
      addr->inet.ip = INADDR_LOOPBACK;
    }

  return PR_SUCCESS;
}

static PRInt32
g_tls_prfiledesc_recv (PRFileDesc     *fd,
		       void           *buf,
		       PRInt32         len,
		       PRIntn          flags,
		       PRIntervalTime  timeout)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;
  PRInt32 ret;

  if (priv->shutdown)
    {
      PR_SetError (PR_IO_ERROR, 0);
      return -1;
    }

  /* "This obsolete parameter must always be zero." */
  g_return_val_if_fail (flags == 0, -1);

  /* We never call PR_Recv with a timeout, though there may
   * be one specified on the underlying socket.
   */
  g_return_val_if_fail (timeout == PR_INTERVAL_NO_TIMEOUT, -1);

  ret = g_pollable_stream_read (G_INPUT_STREAM (priv->tls->base_istream),
				buf, len, priv->tls->read_blocking,
				priv->tls->read_cancellable, &priv->tls->read_error);
  if (ret == -1)
    {
      if (g_error_matches (priv->tls->read_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
	PR_SetError (PR_WOULD_BLOCK_ERROR, 0);
      else
	PR_SetError (PR_IO_ERROR, 0);
      return -1;
    }

  /* GTlsConnectionBase needs to know when handshakes are happening,
   * but NSS prefers to just do them behind your back. We work around
   * this by snooping the traffic to see if the other side is
   * starting/requesting a handshake. This only requires looking at
   * the TLS framing, so it works even if the data is encrypted.
   *
   * This code assumes that NSS never makes reads that cross the
   * header/data boundary. Which is true.
   */
  if (priv->header_length < sizeof (priv->header))
    {
      guint8 *header = NULL;

      /* Reading the start of a new record */
      if (priv->header_length == 0 && ret == sizeof (priv->header))
	{
	  header = buf;
	  priv->header_length = sizeof (priv->header);
	}
      else
	{
	  int header_nread = MIN (ret, sizeof (priv->header) - priv->header_length);

	  /* We got a short read, either now or before, so need to assemble the header. */
	  memcpy (priv->header + priv->header_length, buf, header_nread);
	  priv->header_length += header_nread;
	  if (priv->header_length == sizeof (priv->header))
	    header = priv->header;
	}

      if (header)
	{
	  priv->record_length = TLS_RECORD_LENGTH (header);
	  if (TLS_RECORD_IS_HANDSHAKE (header) && !priv->tls->handshaking)
	    {
	      fflush (stdout);
	      priv->tls->need_handshake = TRUE;
	    }
	}
    }
  else
    {
      priv->record_length -= ret;
      if (priv->record_length == 0)
	priv->header_length = 0;
    }

  return ret;
}

static PRInt32
g_tls_prfiledesc_send (PRFileDesc     *fd,
		       const void     *buf,
		       PRInt32         len,
		       PRIntn          flags,
		       PRIntervalTime  timeout)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;
  PRInt32 ret;

  if (priv->shutdown)
    {
      PR_SetError (PR_IO_ERROR, 0);
      return -1;
    }

  /* "This obsolete parameter must always be zero." */
  g_return_val_if_fail (flags == 0, -1);

  /* We never call PR_Send with a timeout, though there may
   * be one specified on the underlying socket.
   */
  g_return_val_if_fail (timeout == PR_INTERVAL_NO_TIMEOUT, -1);

  ret = g_pollable_stream_write (G_OUTPUT_STREAM (priv->tls->base_ostream),
				 buf, len, priv->tls->write_blocking,
				 priv->tls->write_cancellable, &priv->tls->write_error);
  if (ret == -1)
    {
      if (g_error_matches (priv->tls->write_error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
	PR_SetError (PR_WOULD_BLOCK_ERROR, 0);
      else
	PR_SetError (PR_IO_ERROR, 0);
    }

  return ret;
}

static PRStatus
g_tls_prfiledesc_get_socket_option (PRFileDesc         *fd,
				    PRSocketOptionData *data)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;

  if (data->option == PR_SockOpt_Nonblocking)
    {
      /* NSS wants to know if the socket is blocking or not. But
       * GTlsConnections are only blocking or non-blocking per
       * operation, so the answer is "it depends; why do you want to
       * know?"
       */
      if (priv->tls->handshaking || priv->tls->closing)
	data->value.non_blocking = FALSE;
      else if (!priv->tls->reading)
	data->value.non_blocking = !priv->tls->write_blocking;
      else if (!priv->tls->writing)
	data->value.non_blocking = !priv->tls->read_blocking;
      else if (priv->tls->read_blocking == priv->tls->write_blocking)
	data->value.non_blocking = !priv->tls->read_blocking;
      else
	{
	  // FIXME
	}

      return PR_SUCCESS;
    }

  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRStatus
g_tls_prfiledesc_set_socket_option (PRFileDesc               *fd,
				    const PRSocketOptionData *data)
{
  if (data->option == PR_SockOpt_NoDelay)
    return PR_SUCCESS;

  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRStatus
g_tls_prfiledesc_shutdown (PRFileDesc *fd,
			   PRIntn      how)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;

  /* Gets called after some handshake failures */

  priv->shutdown = TRUE;
  return PR_SUCCESS;
}

static PRStatus
g_tls_prfiledesc_close (PRFileDesc *fd)
{
  GTlsPRFileDescPrivate *priv = (GTlsPRFileDescPrivate *)fd->secret;

  /* This will be called by the SSL layer after doing the SSL close,
   * but we don't want to close the underlying iostream;
   * GTlsConnectionBase will take care of that.
   */
  g_slice_free (GTlsPRFileDescPrivate, priv);
  return PR_SUCCESS;
}

static PRInt32
g_tls_prfiledesc_read (PRFileDesc *fd,
		       void       *buf,
		       PRInt32     len)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt32
g_tls_prfiledesc_write (PRFileDesc *fd,
			const void *buf,
			PRInt32     len)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt32
g_tls_prfiledesc_available (PRFileDesc *fd)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt64
g_tls_prfiledesc_available64 (PRFileDesc *fd)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRStatus
g_tls_prfiledesc_fsync (PRFileDesc *fd)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRInt32
g_tls_prfiledesc_seek (PRFileDesc   *fd,
		       PRInt32       offset,
		       PRSeekWhence  how)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt64
g_tls_prfiledesc_seek64 (PRFileDesc   *fd,
			 PRInt64       offset,
			 PRSeekWhence  how)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRStatus
g_tls_prfiledesc_fileinfo (PRFileDesc *fd,
			   PRFileInfo *info)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRStatus
g_tls_prfiledesc_fileinfo64 (PRFileDesc   *fd,
			     PRFileInfo64 *info)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRInt32
g_tls_prfiledesc_writev (PRFileDesc     *fd,
			 const PRIOVec  *iov,
			 PRInt32         vectors, 
			 PRIntervalTime  timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRStatus
g_tls_prfiledesc_connect (PRFileDesc      *fd,
			  const PRNetAddr *addr,
			  PRIntervalTime   timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRFileDesc*
g_tls_prfiledesc_accept (PRFileDesc     *fd,
			 PRNetAddr      *addr,
			 PRIntervalTime  timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (NULL);
}

static PRStatus
g_tls_prfiledesc_bind (PRFileDesc      *fd,
		       const PRNetAddr *addr)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRStatus
g_tls_prfiledesc_listen (PRFileDesc *fd,
			 PRIntn      backlog)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRInt32
g_tls_prfiledesc_recvfrom (PRFileDesc     *fd,
			   void           *buf,
			   PRInt32         amount,
			   PRIntn          flags,
			   PRNetAddr      *addr,
			   PRIntervalTime  timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt32
g_tls_prfiledesc_sendto (PRFileDesc      *fd,
			 const void      *buf,
			 PRInt32          amount,
			 PRIntn           flags,
			 const PRNetAddr *addr,
			 PRIntervalTime   timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt16
g_tls_prfiledesc_poll (PRFileDesc *fd,
		       PRInt16     how_flags,
		       PRInt16    *p_out_flags)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt32
g_tls_prfiledesc_accept_read (PRFileDesc      *sd,
			      PRFileDesc     **nd,
			      PRNetAddr      **raddr,
			      void            *buf,
			      PRInt32          amount,
			      PRIntervalTime   t)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRInt32
g_tls_prfiledesc_transmit_file (PRFileDesc          *sd,
				PRFileDesc          *fd,
				const void          *headers,
				PRInt32              hlen,
				PRTransmitFileFlags  flags,
				PRIntervalTime       timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRStatus
g_tls_prfiledesc_get_sock_name (PRFileDesc *fd,
				PRNetAddr  *name)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}

static PRInt32
g_tls_prfiledesc_send_file (PRFileDesc          *sd,
			    PRSendFileData      *sfd,
			    PRTransmitFileFlags  flags,
			    PRIntervalTime       timeout)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (-1);
}

static PRStatus
g_tls_prfiledesc_connect_continue (PRFileDesc *fd,
				   PRInt16     out_flags)
{
  PR_SetError (PR_NOT_IMPLEMENTED_ERROR, 0);
  g_return_val_if_reached (PR_FAILURE);
}


static const PRIOMethods g_tls_prfiledesc_methods = {
  PR_DESC_LAYERED,
  g_tls_prfiledesc_close,
  g_tls_prfiledesc_read,
  g_tls_prfiledesc_write,
  g_tls_prfiledesc_available,
  g_tls_prfiledesc_available64,
  g_tls_prfiledesc_fsync,
  g_tls_prfiledesc_seek,
  g_tls_prfiledesc_seek64,
  g_tls_prfiledesc_fileinfo,
  g_tls_prfiledesc_fileinfo64,
  g_tls_prfiledesc_writev,
  g_tls_prfiledesc_connect,
  g_tls_prfiledesc_accept,
  g_tls_prfiledesc_bind,
  g_tls_prfiledesc_listen,
  g_tls_prfiledesc_shutdown,
  g_tls_prfiledesc_recv,
  g_tls_prfiledesc_send,
  g_tls_prfiledesc_recvfrom,
  g_tls_prfiledesc_sendto,
  g_tls_prfiledesc_poll,
  g_tls_prfiledesc_accept_read,
  g_tls_prfiledesc_transmit_file,
  g_tls_prfiledesc_get_sock_name,
  g_tls_prfiledesc_get_peer_name,
  NULL, /* getsockopt (obsolete) */
  NULL, /* setsockopt (obsolete) */
  g_tls_prfiledesc_get_socket_option,
  g_tls_prfiledesc_set_socket_option,
  g_tls_prfiledesc_send_file,
  g_tls_prfiledesc_connect_continue,
  NULL, /* reserved for future use */
  NULL, /* reserved for future use */
  NULL, /* reserved for future use */
  NULL  /* reserved for future use */
};

PRFileDesc *
g_tls_prfiledesc_new (GTlsConnectionNss *nss)
{
  PRFileDesc *prfd = PR_NEWZAP (PRFileDesc);
  GTlsPRFileDescPrivate *priv;

  prfd->methods = &g_tls_prfiledesc_methods;
  prfd->identity = PR_GetUniqueIdentity ("GTls");

  priv = g_slice_new0 (GTlsPRFileDescPrivate);
  prfd->secret = (gpointer)priv;
  priv->tls = G_TLS_CONNECTION_BASE (nss);

  return prfd;
}

