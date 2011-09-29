/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Red Hat, Inc
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

#include "config.h"
#include "glib.h"

#include <errno.h>

#include <nss.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <secmod.h>
#include <ssl.h>

#include "gtlsbackend-nss.h"
#include "gtlscertificate-nss.h"
#include "gtlsclientconnection-nss.h"
#include "gtlsfiledatabase-nss.h"
#include "gtlsserverconnection-nss.h"

GTlsDatabaseNss *g_tls_backend_nss_default_database;
CERTCertDBHandle *g_tls_backend_nss_certdbhandle;
PK11SlotInfo *g_tls_backend_nss_pem_slot;

struct _GTlsBackendNssPrivate
{
  NSSInitContext *context;
};

static void g_tls_backend_nss_interface_init (GTlsBackendInterface *iface);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendNss, g_tls_backend_nss, G_TYPE_OBJECT, 0,
				G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
							       g_tls_backend_nss_interface_init);)

static void
g_tls_backend_nss_init (GTlsBackendNss *backend)
{
  static volatile gsize inited;
  int i;

  backend->priv = G_TYPE_INSTANCE_GET_PRIVATE (backend, G_TYPE_TLS_BACKEND_NSS, GTlsBackendNssPrivate);

  backend->priv->context = NSS_InitContext ("sql:/etc/pki/nssdb", "", "",
					    SECMOD_DB, NULL, 0);

  /* FIXME? */
  NSS_SetDomesticPolicy ();

  if (g_once_init_enter (&inited))
    {
      SECMODModule *pem_module;

      g_tls_backend_nss_certdbhandle = CERT_GetDefaultCertDB ();
      g_tls_backend_nss_default_database = g_object_new (G_TYPE_TLS_DATABASE_NSS, NULL);

      pem_module = SECMOD_LoadUserModule ("library=libnsspem.so name=PEM",
					  NULL, PR_FALSE);
      g_assert (pem_module != NULL);

      /* Find an open slot in the PEM loader; slot 0 is reserved for
       * CA certificates.
       */
      for (i = 1; i <= 8; i++)
	{
	  char *slot_name = g_strdup_printf ("PEM Token #%d", i);
	  PK11SlotInfo *slot = PK11_FindSlotByName (slot_name);
	  SECKEYPublicKeyList *pubkeys;

	  if (!slot)
	    continue;

	  pubkeys = PK11_ListPublicKeysInSlot (slot, NULL);
	  if (!pubkeys)
	    {
	      g_tls_backend_nss_pem_slot = slot;
	      break;
	    }

	  SECKEY_DestroyPublicKeyList (pubkeys);
	  PK11_FreeSlot (slot);
	}

      g_assert (g_tls_backend_nss_pem_slot != NULL);

      g_once_init_leave (&inited, TRUE);
    }
}

static void
g_tls_backend_nss_finalize (GObject *object)
{
  GTlsBackendNss *backend = G_TLS_BACKEND_NSS (object);

  if (backend->priv->context)
    NSS_ShutdownContext (backend->priv->context);

  G_OBJECT_CLASS (g_tls_backend_nss_parent_class)->finalize (object);
}

static void
g_tls_backend_nss_class_init (GTlsBackendNssClass *backend_class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (backend_class);

  g_type_class_add_private (backend_class, sizeof (GTlsBackendNssPrivate));

  gobject_class->finalize = g_tls_backend_nss_finalize;
}

static void
g_tls_backend_nss_class_finalize (GTlsBackendNssClass *backend_class)
{
}

static GTlsDatabase *
g_tls_backend_nss_get_default_database (GTlsBackend *backend)
{
  return g_object_ref (g_tls_backend_nss_default_database);
}

static void
g_tls_backend_nss_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type       = g_tls_certificate_nss_get_type;
  iface->get_client_connection_type = g_tls_client_connection_nss_get_type;
  iface->get_server_connection_type = g_tls_server_connection_nss_get_type;
  iface->get_file_database_type     = g_tls_file_database_nss_get_type;
  iface->get_default_database       = g_tls_backend_nss_get_default_database;
}

void
g_tls_backend_nss_register (GIOModule *module)
{
  g_tls_backend_nss_register_type (G_TYPE_MODULE (module));
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
				  g_tls_backend_nss_get_type(),
				  "nss",
				  0);
}
