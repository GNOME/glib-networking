/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * GIO - GLib Input, Output and Streaming Library
 *
 * Copyright 2011 Collabora, Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, see
 * <http://www.gnu.org/licenses/>.
 *
 * In addition, when the library is used with OpenSSL, a special
 * exception applies. Refer to the LICENSE_EXCEPTION file for details.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#include "gtlsdatabase-gnutls-pkcs11.h"
#include "gtlscertificate-gnutls-pkcs11.h"

#include <gio/gio.h>
#include <glib/gi18n-lib.h>
#include <gnutls/x509.h>

#include <p11-kit/p11-kit.h>
#include <stdlib.h>

#include "pkcs11/gpkcs11pin.h"
#include "pkcs11/gpkcs11slot.h"
#include "pkcs11/gpkcs11util.h"
#include "pkcs11/pkcs11-trust-assertions.h"

static const CK_ATTRIBUTE_TYPE CERTIFICATE_ATTRIBUTE_TYPES[] = {
    CKA_ID, CKA_LABEL, CKA_CLASS, CKA_VALUE
};

static const CK_ATTRIBUTE_TYPE KEY_ATTRIBUTE_TYPES[] = {
    CKA_ID, CKA_LABEL, CKA_CLASS, CKA_KEY_TYPE
};

static void g_tls_database_gnutls_pkcs11_initable_iface_init (GInitableIface *iface);

struct _GTlsDatabaseGnutlsPkcs11
{
  GTlsDatabaseGnutls parent_instance;

  /* no changes after construction */
  CK_FUNCTION_LIST **modules;
  GList *pkcs11_slots;
  GList *trust_uris;
};

G_DEFINE_TYPE_WITH_CODE (GTlsDatabaseGnutlsPkcs11, g_tls_database_gnutls_pkcs11,
                         G_TYPE_TLS_DATABASE_GNUTLS,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_database_gnutls_pkcs11_initable_iface_init));

static gboolean
discover_module_slots_and_options (GTlsDatabaseGnutlsPkcs11   *self,
                                   CK_FUNCTION_LIST_PTR        module,
                                   GError                    **error)
{
  CK_ULONG i, count = 0;
  CK_SLOT_ID *list;
  GPkcs11Slot *slot;
  P11KitUri *uri;
  char *string;
  guint uri_type;
  int ret;
  CK_RV rv;

  /*
   * Ask module for the number of slots. We include slots without tokens
   * since we want to be able to use them if the user inserts a token
   * later.
   */

  rv = (module->C_GetSlotList) (CK_FALSE, NULL, &count);
  if (rv != CKR_OK)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   "Couldn't load list of slots in PKCS#11 module: %s",
                   p11_kit_strerror (rv));
      return FALSE;
    }

  if (count == 0)
    return TRUE;

  /* Actually retrieve the slot ids */
  list = g_new0 (CK_SLOT_ID, count);
  rv = (module->C_GetSlotList) (CK_FALSE, list, &count);
  if (rv != CKR_OK)
    {
      g_set_error (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                   "Couldn't load list of slots in PKCS#11 module: %s",
                   p11_kit_strerror (rv));
      g_free (list);
      return FALSE;
    }

  for (i = 0; i < count; ++i)
    {
      slot = g_object_new (G_TYPE_PKCS11_SLOT,
                           "slot-id", list[i],
                           "module", module,
                           NULL);
      self->pkcs11_slots = g_list_append (self->pkcs11_slots, slot);
    }

  /*
   * Load up relevant options. We use the x-trust-lookup option to determine
   * which slots we can use for looking up trust assertionts.
   */

  string = p11_kit_config_option (module, "x-trust-lookup");
  if (string != NULL)
    {
      uri = p11_kit_uri_new ();
      uri_type = P11_KIT_URI_FOR_TOKEN | P11_KIT_URI_FOR_MODULE_WITH_VERSION;
      ret = p11_kit_uri_parse (string, uri_type, uri);

      if (ret < 0)
        {
          g_message ("couldn't parse configured uri for trust lookups: %s: %s",
                     string, p11_kit_uri_message (ret));
          p11_kit_uri_free (uri);
        }
      else
        {
          self->trust_uris = g_list_append (self->trust_uris, uri);
        }

      free (string);
    }

  return TRUE;
}

static GTlsCertificate *
create_database_pkcs11_certificate (GPkcs11Slot  *slot,
                                    GPkcs11Array *certificate_attrs,
                                    GPkcs11Array *private_key_attrs)
{
  GTlsCertificate *certificate;
  gchar *certificate_uri = NULL;
  gchar *private_key_uri = NULL;
  const CK_ATTRIBUTE *value_attr;
  P11KitUri *uri;
  int ret;

  value_attr = g_pkcs11_array_find (certificate_attrs, CKA_VALUE);
  if (value_attr == NULL)
    return NULL;

  uri = p11_kit_uri_new ();

  /*
   * The PKCS#11 URIs we create for certificates and keys are not bound to
   * the module. They are bound to the token.
   *
   * For example the user could have keys on a smart card token. He could insert
   * this smart card into a different slot, or perhaps change the driver
   * (through an OS upgrade). So the key and certificate should still be
   * referenceable through the URI.
   *
   * We also set a 'pinfile' prompting id, so that users of p11-kit like
   * gnutls can call our callback.
   */

  if (!g_pkcs11_slot_get_token_info (slot, p11_kit_uri_get_token_info (uri)))
    g_return_val_if_reached (NULL);

  ret = p11_kit_uri_set_attributes (uri, certificate_attrs->attrs,
                                    certificate_attrs->count);
  g_return_val_if_fail (ret == P11_KIT_URI_OK, NULL);

  ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, &certificate_uri);
  g_return_val_if_fail (ret == P11_KIT_URI_OK, NULL);

  if (private_key_attrs != NULL)
    {

      /* The URI will keep the token info above, so we just change attributes */

      ret = p11_kit_uri_set_attributes (uri, private_key_attrs->attrs,
                                        private_key_attrs->count);
      g_return_val_if_fail (ret == P11_KIT_URI_OK, NULL);

      ret = p11_kit_uri_format (uri, P11_KIT_URI_FOR_OBJECT_ON_TOKEN, &private_key_uri);
      g_return_val_if_fail (ret == P11_KIT_URI_OK, NULL);
    }

  certificate = g_tls_certificate_gnutls_pkcs11_new (value_attr->pValue,
                                                     value_attr->ulValueLen,
                                                     certificate_uri,
                                                     private_key_uri,
                                                     NULL);

  p11_kit_uri_free (uri);
  g_free (certificate_uri);
  g_free (private_key_uri);

  return certificate;
}

static const gchar *
calculate_peer_for_identity (GSocketConnectable *identity)
{
  const char *peer;

  if (G_IS_NETWORK_ADDRESS (identity))
    peer = g_network_address_get_hostname (G_NETWORK_ADDRESS (identity));
  else if (G_IS_NETWORK_SERVICE (identity))
    peer = g_network_service_get_domain (G_NETWORK_SERVICE (identity));
  else
    peer = NULL;

  return peer;
}

static void
g_tls_database_gnutls_pkcs11_finalize (GObject *object)
{
  GTlsDatabaseGnutlsPkcs11 *self = G_TLS_DATABASE_GNUTLS_PKCS11 (object);
  GList *l;

  for (l = self->pkcs11_slots; l; l = g_list_next (l))
      g_object_unref (l->data);
  g_list_free (self->pkcs11_slots);

  for (l = self->trust_uris; l; l = g_list_next (l))
    p11_kit_uri_free (l->data);
  g_list_free (self->trust_uris);

  if (self->modules)
    p11_kit_modules_release (self->modules);

  G_OBJECT_CLASS (g_tls_database_gnutls_pkcs11_parent_class)->finalize (object);
}

static void
g_tls_database_gnutls_pkcs11_init (GTlsDatabaseGnutlsPkcs11 *self)
{
}

static gboolean
accumulate_stop (gpointer result,
                 gpointer user_data)
{
  return FALSE; /* stop enumeration */
}

static gboolean
accumulate_exists (gpointer result,
                   gpointer user_data)
{
  gboolean *exists = (gboolean *)user_data;
  *exists = TRUE;
  return FALSE; /* stop enumeration */
}

static gboolean
accumulate_first_attributes (gpointer result,
                             gpointer user_data)
{
  GPkcs11Array **attributes = (GPkcs11Array **)user_data;
  g_assert (attributes);
  *attributes = g_pkcs11_array_ref (result);
  return FALSE; /* stop enumeration */
}

static gboolean
accumulate_list_attributes (gpointer result,
                            gpointer user_data)
{
  GList **results = (GList **)user_data;
  g_assert (results);
  *results = g_list_append (*results, g_pkcs11_array_ref (result));
  return TRUE; /* continue enumeration */
}

static gboolean
accumulate_first_object (gpointer result,
                         gpointer user_data)
{
  GObject **object = (GObject **)user_data;
  g_assert (object);
  *object = g_object_ref (result);
  return FALSE; /* stop enumeration */
}

static gboolean
accumulate_list_objects (gpointer result,
                         gpointer user_data)
{
  GList **results = (GList **)user_data;
  g_assert (results);
  *results = g_list_append (*results, g_object_ref (result));
  return TRUE; /* continue enumeration */
}

static GPkcs11EnumerateState
enumerate_call_accumulator (GPkcs11Accumulator accumulator,
                            gpointer           result,
                            gpointer           user_data)
{
  g_assert (accumulator);

  if (!(accumulator) (result, user_data))
    return G_PKCS11_ENUMERATE_STOP;

  return G_PKCS11_ENUMERATE_CONTINUE;
}

static GPkcs11EnumerateState
enumerate_assertion_exists_in_slot (GPkcs11Slot         *slot,
                                    GTlsInteraction     *interaction,
                                    GPkcs11Array        *match,
                                    GPkcs11Accumulator   accumulator,
                                    gpointer             user_data,
                                    GCancellable        *cancellable,
                                    GError             **error)
{
  GPkcs11EnumerateState state;

  state = g_pkcs11_slot_enumerate (slot, interaction, match->attrs, match->count,
                                   FALSE, NULL, 0, accumulate_stop, NULL,
                                   cancellable, error);

  /* A stop means that something matched */
  if (state == G_PKCS11_ENUMERATE_STOP)
    return enumerate_call_accumulator (accumulator, NULL, user_data);

  return state;
}

static GPkcs11EnumerateState
enumerate_assertion_exists_in_database (GTlsDatabaseGnutlsPkcs11   *self,
                                        GTlsInteraction            *interaction,
                                        GPkcs11Array               *match,
                                        GPkcs11Accumulator          accumulator,
                                        gpointer                    user_data,
                                        GCancellable               *cancellable,
                                        GError                    **error)
{
  GPkcs11EnumerateState state = G_PKCS11_ENUMERATE_CONTINUE;
  gboolean slot_matched;
  GPkcs11Slot *slot;
  GList *l, *t;

  for (l = self->pkcs11_slots; l != NULL; l = g_list_next (l))
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return G_PKCS11_ENUMERATE_FAILED;

      slot = l->data;

      /* We only search for assertions on slots that match the trust-lookup uris */
      slot_matched = FALSE;
      for (t = self->trust_uris; !slot_matched && t != NULL; t = g_list_next (t))
          slot_matched = g_pkcs11_slot_matches_uri (slot, t->data);
      if (!slot_matched)
        continue;

      state = enumerate_assertion_exists_in_slot (slot, interaction, match, accumulator,
                                                  user_data, cancellable, error);
      if (state != G_PKCS11_ENUMERATE_CONTINUE)
        break;
  }

  return state;
}

static gboolean
g_tls_database_gnutls_pkcs11_lookup_assertion (GTlsDatabaseGnutlsPkcs11     *self,
                                               GTlsCertificateGnutls        *certificate,
                                               GTlsDatabaseGnutlsAssertion   assertion,
                                               const gchar                  *purpose,
                                               GSocketConnectable           *identity,
                                               GCancellable                 *cancellable,
                                               GError                      **error)
{
  GByteArray *der = NULL;
  gboolean found, ready;
  GPkcs11Array *match;
  const gchar *peer;

  ready = FALSE;
  found = FALSE;
  match = g_pkcs11_array_new ();

  if (assertion == G_TLS_DATABASE_GNUTLS_ANCHORED_CERTIFICATE ||
      assertion == G_TLS_DATABASE_GNUTLS_PINNED_CERTIFICATE)
    {
      g_object_get (certificate, "certificate", &der, NULL);
      g_return_val_if_fail (der, FALSE);
      g_pkcs11_array_add_value (match, CKA_X_CERTIFICATE_VALUE, der->data, der->len);
      g_byte_array_unref (der);

      g_pkcs11_array_add_value (match, CKA_X_PURPOSE, purpose, -1);

      if (assertion == G_TLS_DATABASE_GNUTLS_ANCHORED_CERTIFICATE)
        {
          g_pkcs11_array_add_ulong (match, CKA_X_ASSERTION_TYPE, CKT_X_ANCHORED_CERTIFICATE);
          ready = TRUE;
        }
      else if (assertion == G_TLS_DATABASE_GNUTLS_PINNED_CERTIFICATE)
        {
          g_pkcs11_array_add_ulong (match, CKA_X_ASSERTION_TYPE, CKT_X_PINNED_CERTIFICATE);
          peer = calculate_peer_for_identity (identity);
          if (peer)
            {
              g_pkcs11_array_add_value (match, CKA_X_PEER, peer, -1);
              ready = TRUE;
            }
        }
    }

  if (ready == TRUE)
      enumerate_assertion_exists_in_database (self, NULL, match, accumulate_exists,
                                              &found, cancellable, error);

  g_pkcs11_array_unref (match);
  return found;
}

static GPkcs11EnumerateState
enumerate_keypair_for_certificate (GPkcs11Slot         *slot,
                                   GTlsInteraction     *interaction,
                                   GPkcs11Array        *match_certificate,
                                   GPkcs11Accumulator   accumulator,
                                   gpointer             user_data,
                                   GCancellable        *cancellable,
                                   GError             **error)
{
  static CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
  GPkcs11Array *private_key_attrs = NULL;
  const CK_ATTRIBUTE *id_attribute;
  CK_ATTRIBUTE match[2];
  GTlsCertificate *certificate;
  GPkcs11EnumerateState state;

  /*
   * We need to find a private key that matches the certificate.
   *
   * The PKCS#11 standard strongly suggests the norm that matching certificates
   * and keys have the same CKA_ID. This is how we lookup the key that matches
   * a certificate.
   */

  id_attribute = g_pkcs11_array_find (match_certificate, CKA_ID);
  if (id_attribute == NULL)
    return TRUE;

  match[0].type = CKA_ID;
  match[0].pValue = id_attribute->pValue;
  match[0].ulValueLen = id_attribute->ulValueLen;
  match[1].type = CKA_CLASS;
  match[1].pValue = &key_class;
  match[1].ulValueLen = sizeof (key_class);

  g_assert (private_key_attrs == NULL);
  state = g_pkcs11_slot_enumerate (slot, interaction, match, G_N_ELEMENTS (match), TRUE,
                                   KEY_ATTRIBUTE_TYPES, G_N_ELEMENTS (KEY_ATTRIBUTE_TYPES),
                                   accumulate_first_attributes, &private_key_attrs,
                                   cancellable, error);

  if (state == G_PKCS11_ENUMERATE_FAILED)
    return state;

  state = G_PKCS11_ENUMERATE_CONTINUE;
  if (private_key_attrs)
    {
      /* We searched for public key (see above) so change attributes to look like private */
      g_pkcs11_array_set_ulong (private_key_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
      certificate = create_database_pkcs11_certificate (slot, match_certificate,
                                                        private_key_attrs);
      g_pkcs11_array_unref (private_key_attrs);

      if (certificate)
        {
          state = enumerate_call_accumulator (accumulator, certificate, user_data);
          g_object_unref (certificate);
        }
    }

  return state;
}

static GPkcs11EnumerateState
enumerate_keypairs_in_slot (GPkcs11Slot         *slot,
                            GTlsInteraction     *interaction,
                            CK_ATTRIBUTE_PTR     match,
                            CK_ULONG             match_count,
                            GPkcs11Accumulator   accumulator,
                            gpointer             user_data,
                            GCancellable        *cancellable,
                            GError             **error)
{
  GPkcs11EnumerateState state;
  GList *results = NULL;
  GList *l;

  /*
   * Find all the certificates that match for this slot, and then below
   * we lookup to see if there's a private key for any of them.
   *
   * Note that we shouldn't be doing two find operations at once, because
   * this may use too many sessions on smart cards and fragile drivers. So
   * that's why we list all certificates, complete that find operation, and
   * then do more find ops looking for private keys.
   */

  state = g_pkcs11_slot_enumerate (slot, interaction, match, match_count, FALSE,
                                   CERTIFICATE_ATTRIBUTE_TYPES,
                                   G_N_ELEMENTS (CERTIFICATE_ATTRIBUTE_TYPES),
                                   accumulate_list_attributes, &results,
                                   cancellable, error);
  if (state == G_PKCS11_ENUMERATE_CONTINUE)
    {
      for (l = results; l != NULL; l = g_list_next (l))
        {
          state = enumerate_keypair_for_certificate (slot, interaction, l->data, accumulator,
                                                     user_data, cancellable, error);
          if (state != G_PKCS11_ENUMERATE_CONTINUE)
            break;
        }
    }

  for (l = results; l != NULL; l = g_list_next (l))
    g_pkcs11_array_unref (l->data);
  g_list_free (results);

  return state;
}

typedef struct {
  GPkcs11Accumulator accumulator;
  gpointer user_data;
  GPkcs11Slot *slot;
} enumerate_certificates_closure;

static gboolean
accumulate_wrap_into_certificate (gpointer result,
                                  gpointer user_data)
{
  GPkcs11EnumerateState state = G_PKCS11_ENUMERATE_CONTINUE;
  enumerate_certificates_closure *closure = user_data;
  GTlsCertificate *certificate;

  certificate = create_database_pkcs11_certificate (closure->slot,
                                                    result, NULL);
  if (certificate)
    {
      state = enumerate_call_accumulator (closure->accumulator, certificate,
                                          closure->user_data);
      g_object_unref (certificate);
    }

  return (state == G_PKCS11_ENUMERATE_CONTINUE);
}

static GPkcs11EnumerateState
enumerate_certificates_in_slot (GPkcs11Slot         *slot,
                                GTlsInteraction     *interaction,
                                CK_ATTRIBUTE_PTR     match,
                                CK_ULONG             match_count,
                                GPkcs11Accumulator   accumulator,
                                gpointer             user_data,
                                GCancellable        *cancellable,
                                GError             **error)
{
  enumerate_certificates_closure closure = { accumulator, user_data, slot };

  /*
   * We create the certificates inline, so we can stop the enumeration early
   * if only one certificate is necessary, but a whole bunch match. We provide
   * our own accumulator here, turning the attributes into certificates and
   * then calling the original accumulator.
   */

  return g_pkcs11_slot_enumerate (slot, interaction, match, match_count, FALSE,
                                  CERTIFICATE_ATTRIBUTE_TYPES,
                                  G_N_ELEMENTS (CERTIFICATE_ATTRIBUTE_TYPES),
                                  accumulate_wrap_into_certificate,
                                  &closure, cancellable, error);
}

static GPkcs11EnumerateState
enumerate_certificates_in_database (GTlsDatabaseGnutlsPkcs11  *self,
                                    GTlsInteraction           *interaction,
                                    GTlsDatabaseLookupFlags    flags,
                                    CK_ATTRIBUTE_PTR           match,
                                    CK_ULONG                   match_count,
                                    P11KitUri                 *match_slot_to_uri,
                                    GPkcs11Accumulator         accumulator,
                                    gpointer                   user_data,
                                    GCancellable              *cancellable,
                                    GError                   **error)
{
  GPkcs11EnumerateState state = G_PKCS11_ENUMERATE_CONTINUE;
  GPkcs11Slot *slot;
  GList *l;

  /* These are the flags we support */
  if (flags & ~(G_TLS_DATABASE_LOOKUP_KEYPAIR))
    return G_PKCS11_ENUMERATE_CONTINUE;

  for (l = self->pkcs11_slots; l; l = g_list_next (l))
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        return G_PKCS11_ENUMERATE_FAILED;

      slot = l->data;

      /* If the slot doesn't match the URI (when one is present) nothing matches */
      if (match_slot_to_uri && !g_pkcs11_slot_matches_uri (slot, match_slot_to_uri))
        continue;

      if (flags & G_TLS_DATABASE_LOOKUP_KEYPAIR)
        {
          state = enumerate_keypairs_in_slot (slot, interaction, match,
                                              match_count, accumulator, user_data,
                                              cancellable, error);

        }
      else
        {
          state = enumerate_certificates_in_slot (slot, interaction, match,
                                                  match_count, accumulator,
                                                  user_data, cancellable, error);
        }

      if (state != G_PKCS11_ENUMERATE_CONTINUE)
        break;
    }

  return state;
}

static GTlsCertificate *
g_tls_database_gnutls_pkcs11_lookup_certificate_issuer (GTlsDatabase             *database,
                                                        GTlsCertificate          *certificate,
                                                        GTlsInteraction          *interaction,
                                                        GTlsDatabaseLookupFlags   flags,
                                                        GCancellable             *cancellable,
                                                        GError                  **error)
{
  GTlsDatabaseGnutlsPkcs11 *self = G_TLS_DATABASE_GNUTLS_PKCS11 (database);
  GTlsCertificate *result = NULL;
  GPkcs11Array *match = NULL;
  gnutls_x509_crt_t cert;
  gnutls_datum_t dn;
  int gerr;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (certificate), NULL);

  /* Dig out the issuer of this certificate */
  cert = g_tls_certificate_gnutls_get_cert (G_TLS_CERTIFICATE_GNUTLS (certificate));
  gerr = gnutls_x509_crt_get_raw_issuer_dn (cert, &dn);
  if (gerr < 0)
    {
      g_warning ("failed to get issuer of certificate: %s", gnutls_strerror (gerr));
      return NULL;
    }

  match = g_pkcs11_array_new ();
  g_pkcs11_array_add_ulong (match, CKA_CLASS, CKO_CERTIFICATE);
  g_pkcs11_array_add_ulong (match, CKA_CERTIFICATE_TYPE, CKC_X_509);
  g_pkcs11_array_add_value (match, CKA_SUBJECT, dn.data, dn.size);
  gnutls_free (dn.data);

  enumerate_certificates_in_database (self, interaction, flags, match->attrs,
                                      match->count, NULL, accumulate_first_object,
                                      &result, cancellable, error);
  g_pkcs11_array_unref (match);
  return result;
}

static GList *
g_tls_database_gnutls_pkcs11_lookup_certificates_issued_by (GTlsDatabase             *database,
                                                            GByteArray               *issuer_subject,
                                                            GTlsInteraction          *interaction,
                                                            GTlsDatabaseLookupFlags   flags,
                                                            GCancellable             *cancellable,
                                                            GError                  **error)
{
  GTlsDatabaseGnutlsPkcs11 *self = G_TLS_DATABASE_GNUTLS_PKCS11 (database);
  GList *l, *results = NULL;
  GPkcs11Array *match = NULL;
  GPkcs11EnumerateState state;

  g_return_val_if_fail (issuer_subject, NULL);

  match = g_pkcs11_array_new ();
  g_pkcs11_array_add_ulong (match, CKA_CLASS, CKO_CERTIFICATE);
  g_pkcs11_array_add_ulong (match, CKA_CERTIFICATE_TYPE, CKC_X_509);
  g_pkcs11_array_add_value (match, CKA_ISSUER, issuer_subject->data, issuer_subject->len);

  state = enumerate_certificates_in_database (self, interaction, flags, match->attrs,
                                              match->count, NULL, accumulate_list_objects,
                                              &results, cancellable, error);

  /* Could have had partial success, don't leak memory */
  if (state == G_PKCS11_ENUMERATE_FAILED)
    {
      for (l = results; l != NULL; l = g_list_next (l))
        g_object_unref (l->data);
      g_list_free (results);
      results = NULL;
    }

  g_pkcs11_array_unref (match);
  return results;
}

static gchar *
g_tls_database_gnutls_pkcs11_create_certificate_handle (GTlsDatabase    *database,
                                                        GTlsCertificate *certificate)
{
  GTlsCertificateGnutlsPkcs11 *pkcs11_cert;

  if (!G_IS_TLS_CERTIFICATE_GNUTLS_PKCS11 (certificate))
    return NULL;

  pkcs11_cert = G_TLS_CERTIFICATE_GNUTLS_PKCS11 (certificate);
  return g_tls_certificate_gnutls_pkcs11_build_certificate_uri (pkcs11_cert, NULL);
}

static GTlsCertificate *
g_tls_database_gnutls_pkcs11_lookup_certificate_for_handle (GTlsDatabase             *database,
                                                            const gchar              *handle,
                                                            GTlsInteraction          *interaction,
                                                            GTlsDatabaseLookupFlags   flags,
                                                            GCancellable             *cancellable,
                                                            GError                  **error)
{
  GTlsDatabaseGnutlsPkcs11 *self = G_TLS_DATABASE_GNUTLS_PKCS11 (database);
  GTlsCertificate *result = NULL;
  P11KitUri *uri;
  CK_ATTRIBUTE_PTR match;
  CK_ULONG match_count;
  int ret;

  /* The handle is a PKCS#11 URI */

  /* These are the flags we support */
  if (flags & ~(G_TLS_DATABASE_LOOKUP_KEYPAIR))
    return NULL;

  uri = p11_kit_uri_new ();
  if (uri == NULL)
    g_error ("out of memory in p11_kit_uri_new()");

  ret = p11_kit_uri_parse (handle, P11_KIT_URI_FOR_OBJECT_ON_TOKEN_AND_MODULE |
                           P11_KIT_URI_FOR_MODULE_WITH_VERSION, uri);
  if (ret == P11_KIT_URI_NO_MEMORY)
    {
      g_error ("out of memory in p11_kit_uri_parse()");
    }
  else if (ret != P11_KIT_URI_OK)
    {
      p11_kit_uri_free (uri);
      g_set_error (error, G_PKCS11_ERROR, G_PKCS11_ERROR_BAD_URI,
                   "Invalid PKCS#11 URI: %s", handle);
      return NULL;
    }

  match = p11_kit_uri_get_attributes (uri, &match_count);
  enumerate_certificates_in_database (self, interaction, flags, match, match_count,
                                      uri, accumulate_first_object, &result,
                                      cancellable, error);

  p11_kit_uri_free (uri);
  return result;
}

#define BUILD_CERTIFICATE_CHAIN_RECURSION_LIMIT 10

enum {
  STATUS_FAILURE,
  STATUS_INCOMPLETE,
  STATUS_SELFSIGNED,
  STATUS_ANCHORED,
  STATUS_RECURSION_LIMIT_REACHED
};

static gboolean
is_self_signed (GTlsCertificateGnutls *certificate)
{
  const gnutls_x509_crt_t cert = g_tls_certificate_gnutls_get_cert (certificate);
  return (gnutls_x509_crt_check_issuer (cert, cert) > 0);
}

static gint
build_certificate_chain (GTlsDatabaseGnutlsPkcs11  *self,
                         GTlsCertificateGnutls     *certificate,
                         GTlsCertificateGnutls     *previous,
                         gboolean                   certificate_is_from_db,
                         guint                      recursion_depth,
                         const gchar               *purpose,
                         GSocketConnectable        *identity,
                         GTlsInteraction           *interaction,
                         GCancellable              *cancellable,
                         GTlsCertificateGnutls    **anchor,
                         GError                   **error)
{
  GTlsCertificate *issuer;
  gint status;

  if (recursion_depth++ > BUILD_CERTIFICATE_CHAIN_RECURSION_LIMIT)
    return STATUS_RECURSION_LIMIT_REACHED;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return STATUS_FAILURE;

  /* Look up whether this certificate is an anchor */
  if (g_tls_database_gnutls_pkcs11_lookup_assertion (self, certificate,
                                                     G_TLS_DATABASE_GNUTLS_ANCHORED_CERTIFICATE,
                                                     purpose, identity, cancellable, error))
    {
      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
      *anchor = certificate;
      return STATUS_ANCHORED;
    }
  else if (*error)
    {
      return STATUS_FAILURE;
    }

  /* Is it self-signed? */
  if (is_self_signed (certificate))
    {
      /*
       * Since at this point we would fail with 'self-signed', can we replace
       * this certificate with one from the database and do better?
       */
      if (previous && !certificate_is_from_db)
        {
          issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (self),
                                                             G_TLS_CERTIFICATE (previous),
                                                             interaction,
                                                             G_TLS_DATABASE_LOOKUP_NONE,
                                                             cancellable, error);
          if (*error)
            {
              return STATUS_FAILURE;
            }
          else if (issuer)
            {
              /* Replaced with certificate in the db, restart step again with this certificate */
              g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
              certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);
              g_tls_certificate_gnutls_set_issuer (previous, certificate);
              g_object_unref (issuer);

              return build_certificate_chain (self, certificate, previous, TRUE, recursion_depth,
                                              purpose, identity, interaction, cancellable, anchor, error);
            }
        }

      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
      return STATUS_SELFSIGNED;
    }

  previous = certificate;

  /* Bring over the next certificate in the chain */
  issuer = g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (certificate));
  if (issuer)
    {
      g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
      certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);

      status = build_certificate_chain (self, certificate, previous, FALSE, recursion_depth,
                                        purpose, identity, interaction, cancellable, anchor, error);
      if (status != STATUS_INCOMPLETE)
        {
          return status;
        }
    }

  /* Search for the next certificate in chain */
  issuer = g_tls_database_lookup_certificate_issuer (G_TLS_DATABASE (self),
                                                     G_TLS_CERTIFICATE (certificate),
                                                     interaction,
                                                     G_TLS_DATABASE_LOOKUP_NONE,
                                                     cancellable, error);
  if (*error)
    return STATUS_FAILURE;

  if (!issuer)
    return STATUS_INCOMPLETE;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (issuer), STATUS_FAILURE);
  g_tls_certificate_gnutls_set_issuer (certificate, G_TLS_CERTIFICATE_GNUTLS (issuer));
  certificate = G_TLS_CERTIFICATE_GNUTLS (issuer);
  g_object_unref (issuer);

  return build_certificate_chain (self, certificate, previous, TRUE, recursion_depth,
                                  purpose, identity, interaction, cancellable, anchor, error);
}

static GTlsCertificateFlags
double_check_before_after_dates (GTlsCertificateGnutls *chain)
{
  GTlsCertificateFlags gtls_flags = 0;
  gnutls_x509_crt_t cert;
  time_t t, now;

  now = time (NULL);
  while (chain)
    {
      cert = g_tls_certificate_gnutls_get_cert (chain);
      t = gnutls_x509_crt_get_activation_time (cert);
      if (t == (time_t) -1 || t > now)
        gtls_flags |= G_TLS_CERTIFICATE_NOT_ACTIVATED;

      t = gnutls_x509_crt_get_expiration_time (cert);
      if (t == (time_t) -1 || t < now)
        gtls_flags |= G_TLS_CERTIFICATE_EXPIRED;

      chain = G_TLS_CERTIFICATE_GNUTLS (g_tls_certificate_get_issuer
                                        (G_TLS_CERTIFICATE (chain)));
    }

  return gtls_flags;
}

static void
convert_certificate_chain_to_gnutls (GTlsCertificateGnutls  *chain,
                                     gnutls_x509_crt_t     **gnutls_chain,
                                     guint                  *gnutls_chain_length)
{
  GTlsCertificate *cert;
  guint i;

  g_assert (gnutls_chain);
  g_assert (gnutls_chain_length);

  for (*gnutls_chain_length = 0, cert = G_TLS_CERTIFICATE (chain);
       cert; cert = g_tls_certificate_get_issuer (cert))
    ++(*gnutls_chain_length);

  *gnutls_chain = g_new0 (gnutls_x509_crt_t, *gnutls_chain_length);

  for (i = 0, cert = G_TLS_CERTIFICATE (chain);
       cert; cert = g_tls_certificate_get_issuer (cert), ++i)
    (*gnutls_chain)[i] = g_tls_certificate_gnutls_get_cert (G_TLS_CERTIFICATE_GNUTLS (cert));

  g_assert (i == *gnutls_chain_length);
}

static GTlsCertificateFlags
g_tls_database_gnutls_pkcs11_verify_chain (GTlsDatabase             *database,
                                           GTlsCertificate          *chain,
                                           const gchar              *purpose,
                                           GSocketConnectable       *identity,
                                           GTlsInteraction          *interaction,
                                           GTlsDatabaseVerifyFlags   flags,
                                           GCancellable             *cancellable,
                                           GError                  **error)
{
  GTlsDatabaseGnutlsPkcs11 *self;
  GTlsCertificateFlags result;
  GTlsCertificateGnutls *certificate;
  GError *err = NULL;
  GTlsCertificateGnutls *anchor;
  guint gnutls_result;
  gnutls_x509_crt_t *certs, *anchors;
  guint certs_length, anchors_length;
  gint status, gerr;
  guint recursion_depth = 0;

  g_return_val_if_fail (G_IS_TLS_CERTIFICATE_GNUTLS (chain),
                        G_TLS_CERTIFICATE_GENERIC_ERROR);
  g_assert (purpose);

  self = G_TLS_DATABASE_GNUTLS_PKCS11 (database);
  certificate = G_TLS_CERTIFICATE_GNUTLS (chain);

  /* First check for pinned certificate */
  if (g_tls_database_gnutls_pkcs11_lookup_assertion (self, certificate,
                                                     G_TLS_DATABASE_GNUTLS_PINNED_CERTIFICATE,
                                                     purpose, identity, cancellable, &err))
    {
      /*
       * A pinned certificate is verified on its own, without any further
       * verification.
       */
      g_tls_certificate_gnutls_set_issuer (certificate, NULL);
      return 0;
    }

  if (err)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  anchor = NULL;
  status = build_certificate_chain (self, certificate, NULL, FALSE, recursion_depth,
                                    purpose, identity, interaction, cancellable, &anchor, &err);
  if (status == STATUS_FAILURE)
    {
      g_propagate_error (error, err);
      return G_TLS_CERTIFICATE_GENERIC_ERROR;
    }

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  convert_certificate_chain_to_gnutls (G_TLS_CERTIFICATE_GNUTLS (chain),
                                       &certs, &certs_length);

  if (anchor)
    {
      g_assert (g_tls_certificate_get_issuer (G_TLS_CERTIFICATE (anchor)) == NULL);
      convert_certificate_chain_to_gnutls (G_TLS_CERTIFICATE_GNUTLS (anchor),
                                           &anchors, &anchors_length);
    }
  else
    {
      anchors = NULL;
      anchors_length = 0;
    }

  gerr = gnutls_x509_crt_list_verify (certs, certs_length,
                                      anchors, anchors_length,
                                      NULL, 0, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT,
                                      &gnutls_result);

  g_free (certs);
  g_free (anchors);

  if (gerr != 0)
    return G_TLS_CERTIFICATE_GENERIC_ERROR;
  else if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return G_TLS_CERTIFICATE_GENERIC_ERROR;

  result = g_tls_certificate_gnutls_convert_flags (gnutls_result);

  /*
   * We have to check these ourselves since gnutls_x509_crt_list_verify
   * won't bother if it gets an UNKNOWN_CA.
   */
  result |= double_check_before_after_dates (G_TLS_CERTIFICATE_GNUTLS (chain));

  if (identity)
    result |= g_tls_certificate_gnutls_verify_identity (G_TLS_CERTIFICATE_GNUTLS (chain),
                                                        identity);

  return result;
}

static void
g_tls_database_gnutls_pkcs11_class_init (GTlsDatabaseGnutlsPkcs11Class *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GTlsDatabaseClass *database_class = G_TLS_DATABASE_CLASS (klass);

  gobject_class->finalize = g_tls_database_gnutls_pkcs11_finalize;

  database_class->create_certificate_handle = g_tls_database_gnutls_pkcs11_create_certificate_handle;
  database_class->lookup_certificate_issuer = g_tls_database_gnutls_pkcs11_lookup_certificate_issuer;
  database_class->lookup_certificates_issued_by = g_tls_database_gnutls_pkcs11_lookup_certificates_issued_by;
  database_class->lookup_certificate_for_handle = g_tls_database_gnutls_pkcs11_lookup_certificate_for_handle;
  database_class->verify_chain = g_tls_database_gnutls_pkcs11_verify_chain;
}

static gboolean
g_tls_database_gnutls_pkcs11_initable_init (GInitable     *initable,
                                            GCancellable  *cancellable,
                                            GError       **error)
{
  GTlsDatabaseGnutlsPkcs11 *self = G_TLS_DATABASE_GNUTLS_PKCS11 (initable);
  GError *err = NULL;
  gboolean any_success = FALSE;
  gboolean any_failure = FALSE;
  guint i;

  g_return_val_if_fail (!self->modules, FALSE);

  self->modules = p11_kit_modules_load (NULL, 0);
  if (self->modules == NULL) {
    g_set_error_literal (error, G_PKCS11_ERROR, CKR_FUNCTION_FAILED, p11_kit_message ());
    return FALSE;
  }

  for (i = 0; self->modules[i] != NULL; i++)
    {
      if (g_cancellable_set_error_if_cancelled (cancellable, error))
        {
          any_failure = TRUE;
          any_success = FALSE;
          break;
        }

      if (discover_module_slots_and_options (self, self->modules[i], &err))
        {
          /* A module was setup correctly */
          any_success = TRUE;
          g_clear_error (error);
        }
      else
        {
          /* No module success, first module failure */
          if (!any_success && !any_failure)
            g_propagate_error (error, err);
          any_failure = TRUE;
        }
    }

  return (any_failure && !any_success) ? FALSE : TRUE;
}

static void
g_tls_database_gnutls_pkcs11_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_database_gnutls_pkcs11_initable_init;
}

GTlsDatabase *
g_tls_database_gnutls_pkcs11_new (GError **error)
{
  g_return_val_if_fail (!error || !*error, NULL);
  return g_initable_new (G_TYPE_TLS_DATABASE_GNUTLS_PKCS11, NULL, error, NULL);
}
