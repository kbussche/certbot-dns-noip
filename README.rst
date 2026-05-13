certbot-dns-noip
================

No-IP_ DNS Authenticator plugin for Certbot_.

This plugin automates the process of completing a ``dns-01`` challenge by
creating and removing TXT records in your No-IP DNS zone using the `No-IP DNS API`_.

.. _No-IP: https://www.noip.com
.. _Certbot: https://certbot.eff.org
.. _No-IP DNS API: https://developer.noip.com


Installation
------------

.. code-block:: shell

   pip install certbot-dns-noip

Or install from source for development:

.. code-block:: shell

   pip install -e ".[test]"


Named Arguments
---------------

.. code-block:: none

   --dns-noip-credentials PATH    No-IP credentials INI file (required)
   --dns-noip-propagation-seconds INT
                                  Seconds to wait for DNS propagation (default: 30)


Credentials
-----------

Create a credentials INI file with your No-IP API key:

.. code-block:: ini

   dns_noip_api_key = YOUR_NOIP_API_KEY

Restrict permissions on this file:

.. code-block:: shell

   chmod 600 /etc/letsencrypt/noip.ini


Usage
-----

Single domain:

.. code-block:: shell

   certbot certonly \
     --authenticator dns-noip \
     --dns-noip-credentials /etc/letsencrypt/noip.ini \
     -d example.com

Wildcard certificate:

.. code-block:: shell

   certbot certonly \
     --authenticator dns-noip \
     --dns-noip-credentials /etc/letsencrypt/noip.ini \
     -d "*.example.com" \
     -d example.com


How It Works
------------

1. Certbot requests a ``dns-01`` challenge for your domain.
2. The plugin calls the No-IP API to create a ``_acme-challenge`` TXT record containing
   the challenge token.
3. If a TXT rrset already exists at that name (e.g., when issuing for both ``example.com``
   and ``*.example.com``), the new value is merged into the existing rrset using the
   `replace-rdata`_ endpoint so both values coexist simultaneously.
4. After the challenge is verified, the plugin removes only the challenge value it added,
   preserving any other TXT values that may be present.

.. _replace-rdata: https://developer.noip.com/reference/v1-dns-records-replace-rdata


Development
-----------

Run tests:

.. code-block:: shell

   pytest src/


License
-------

Apache 2.0
