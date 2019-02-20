import weakref

from charms.reactive import Endpoint
from charms.reactive import when, when_not
from charms.reactive import set_flag, clear_flag, toggle_flag

from .tls_certificates_common import (
    CertificateRequest,
    Certificate,
    VersionedProtocol,
)


class TlsProvides(Endpoint):
    """
    The provider's side of the interface protocol.

    The following flags may be set:

      * `{endpoint_name}.available`
        Whenever any clients are joined.

      * `{endpoint_name}.certs.requested`
        When there are new certificate requests of any kind to be processed.
        The requests can be accessed via [new_requests][].

      * `{endpoint_name}.server.certs.requested`
        When there are new server certificate requests to be processed.
        The requests can be accessed via [new_server_requests][].

      * `{endpoint_name}.client.certs.requested`
        When there are new client certificate requests to be processed.
        The requests can be accessed via [new_client_requests][].

    [Certificate]: common.md#tls_certificates_common.Certificate
    [CertificateRequest]: common.md#tls_certificates_common.CertificateRequest
    [all_requests]: provides.md#provides.TlsProvides.all_requests
    [new_requests]: provides.md#provides.TlsProvides.new_requests
    [new_server_requests]: provides.md#provides.TlsProvides.new_server_requests
    [new_client_requests]: provides.md#provides.TlsProvides.new_client_requests
    """
    def _protocol(self, relation):
        if not hasattr(self, '_protocols'):
            ps = self._protocols = {}
            for relation in self.relations:
                ps[relation] = VersionedProtocol.negotiate(relation)
        return self._protocols[relation]

    @when('endpoint.{endpoint_name}.joined')
    def joined(self):
        set_flag(self.expand_name('{endpoint_name}.available'))
        toggle_flag(self.expand_name('{endpoint_name}.certs.requested'),
                    self.new_requests)
        toggle_flag(self.expand_name('{endpoint_name}.server.certs.requested'),
                    self.new_server_requests)
        toggle_flag(self.expand_name('{endpoint_name}.client.certs.requested'),
                    self.new_client_requests)
        # For backwards compatibility, set the old "cert" flags as well
        toggle_flag(self.expand_name('{endpoint_name}.server.cert.requested'),
                    self.new_server_requests)
        toggle_flag(self.expand_name('{endpoint_name}.client.cert.requested'),
                    self.new_client_requests)

    @when_not('endpoint.{endpoint_name}.joined')
    def broken(self):
        clear_flag(self.expand_name('{endpoint_name}.available'))
        clear_flag(self.expand_name('{endpoint_name}.certs.requested'))
        clear_flag(self.expand_name('{endpoint_name}.server.certs.requested'))
        clear_flag(self.expand_name('{endpoint_name}.client.certs.requested'))

    def set_ca(self, certificate_authority):
        """
        Publish the CA to all related applications.
        """
        for relation in self.relations:
            protocol = self._protocol(relation)
            protocol.set_root_ca_cert(certificate_authority)

    def set_chain(self, chain):
        """
        Publish the chain of trust to all related applications.
        """
        for relation in self.relations:
            protocol = self._protocol(relation)
            protocol.set_root_ca_chain(chain)

    def set_client_cert(self, cert, key):
        """
        Deprecated.  This is only for backwards compatibility.

        Publish a globally shared client cert and key.
        """
        for relation in self.relations:
            protocol = self._protocol(relation)
            protocol.set_global_client_cert(cert, key)

    def set_server_cert(self, scope, cert, key):
        """
        Deprecated.  Use one of the [new_requests][] collections and
        `request.set_cert()` instead.

        Set the server cert and key for the request identified by `scope`.
        """
        for relation in self.relations:
            protocol = self._protocol(relation)
            if scope in protocol.requests:
                protocol.requests[scope].set_cert(cert, key)
                break

    def set_server_multicerts(self, scope):
        """
        Deprecated.  Done automatically.
        """
        pass

    def add_server_cert(self, scope, cn, cert, key):
        '''
        Deprecated.  Use `request.set_cert()` instead.
        '''
        self.set_server_cert(scope, cert, key)

    def get_server_requests(self):
        """
        Deprecated.  Use the [new_requests][] or [server_requests][]
        collections instead.

        One provider can have many requests to generate server certificates.
        Return a map of all server request objects indexed by a unique
        identifier.
        """
        return {req.request_id: req for req in self.new_server_requests}

    @property
    def all_requests(self):
        """
        List of all requests that have been made.

        Each will be an instance of [CertificateRequest][].

        Example usage:

        ```python
        @when('certs.regen',
              'tls.certs.available')
        def regen_all_certs():
            tls = endpoint_from_flag('tls.certs.available')
            for request in tls.all_requests:
                cert, key = generate_cert(request.cert_type,
                                          request.common_name,
                                          request.sans)
                request.set_cert(cert, key)
        ```
        """
        requests = []
        for relation in self.relations:
            protocol = self._protocol(relation)
            requests.extend(protocol.requests.values())
        return requests

    @property
    def new_requests(self):
        """
        Filtered view of [all_requests][] that only includes requests that
        haven't been handled.

        Each will be an instance of [CertificateRequest][].

        This collection can also be further filtered by request type using
        [new_server_requests][] or [new_client_requests][].

        Example usage:

        ```python
        @when('tls.certs.requested')
        def gen_certs():
            tls = endpoint_from_flag('tls.certs.requested')
            for request in tls.new_requests:
                cert, key = generate_cert(request.cert_type,
                                          request.common_name,
                                          request.sans)
                request.set_cert(cert, key)
        ```
        """
        return [req for req in self.all_requests if not req.is_handled]

    @property
    def new_server_requests(self):
        """
        Filtered view of [new_requests][] that only includes server cert
        requests.

        Each will be an instance of [CertificateRequest][].

        Example usage:

        ```python
        @when('tls.server.certs.requested')
        def gen_server_certs():
            tls = endpoint_from_flag('tls.server.certs.requested')
            for request in tls.new_server_requests:
                cert, key = generate_server_cert(request.common_name,
                                                 request.sans)
                request.set_cert(cert, key)
        ```
        """
        return [req for req in self.new_requests if req.cert_type == 'server']

    @property
    def new_client_requests(self):
        """
        Filtered view of [new_requests][] that only includes client cert
        requests.

        Each will be an instance of [CertificateRequest][].

        Example usage:

        ```python
        @when('tls.client.certs.requested')
        def gen_client_certs():
            tls = endpoint_from_flag('tls.client.certs.requested')
            for request in tls.new_client_requests:
                cert, key = generate_client_cert(request.common_name,
                                                 request.sans)
                request.set_cert(cert, key)
        ```
        """
        return [req for req in self.new_requests if req.cert_type == 'client']

    @property
    def all_published_certs(self):
        """
        List of all [Certificate][] instances that this provider has published
        for all related applications.
        """
        certs = []
        for relation in self.relations:
            protocol = self._protocol(relation)
            certs.extend(protocol.responses.values())
        return certs


class ProvidesV1(VersionedProtocol):
    VERSION = 1

    def upgrade_from(self, old_version):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.requests = {}
        self.responses = {}
        self._read_requests()
        self._read_responses()

    def _read_requests(self):
        for unit in self.relation.joined_units:
            # handle older single server cert request
            common_name = unit.received_raw.get('common_name')
            if common_name:
                request_id = '.'.join((unit.relation.relation_id,
                                       unit.unit_name,
                                       common_name))
                req = self.requests[request_id] = CertificateRequest(
                    request_id=request_id,
                    cert_type='server',
                    cert_name=unit.received_raw['certificate_name'],
                    common_name=common_name,
                    sans=unit.received['sans'],
                    unit=unit,
                    protocol=weakref.proxy(self),
                )
                # patch in to req for easier filtering later
                req._is_top_level_server_cert_request = True

            # handle mutli server cert requests
            reqs = unit.received['cert_requests'] or {}
            for common_name, req in reqs.items():
                request_id = '.'.join((unit.relation.relation_id,
                                       unit.unit_name,
                                       common_name))
                req = self.requests[request_id] = CertificateRequest(
                    request_id=request_id,
                    cert_type='server',
                    cert_name=common_name,
                    common_name=common_name,
                    sans=req['sans'],
                    unit=unit,
                    protocol=weakref.proxy(self),
                )
                # patch in to req for easier filtering later
                req._is_top_level_server_cert_request = False

            # handle client cert requests
            reqs = unit.received['client_cert_requests'] or {}
            for common_name, req in reqs.items():
                request_id = '.'.join((unit.relation.relation_id,
                                       unit.unit_name,
                                       common_name))
                req = self.requests[request_id] = CertificateRequest(
                    request_id=request_id,
                    cert_type='client',
                    cert_name=common_name,
                    common_name=common_name,
                    sans=req['sans'],
                    unit=unit,
                    protocol=weakref.proxy(self),
                )
                # patch in to req for easier filtering later
                req._is_top_level_server_cert_request = False

    def _read_responses(self):
        for request in self.requests.values():
            rel = request.relation
            unit_name = request.unit.unit_name.replace('/', '_')
            # handle top-level server cert requests
            if request._is_top_level_server_cert_request:
                cert = rel.to_publish_raw['{}.server.cert'.format(unit_name)]
                key = rel.to_publish_raw['{}.server.key'.format(unit_name)]
                if cert and key:
                    self.responses[request.request_id] = Certificate(
                        request_id=request.request_id,
                        cert_type=request.cert_type,
                        common_name=request.common_name,
                        cert=cert,
                        key=key,
                    )
            else:
                if request.cert_type == 'server':
                    publish_key = '{}.processed_requests'
                elif request.cert_type == 'client':
                    publish_key = '{}.processed_client_requests'
                else:
                    raise ValueError('Unknown cert_type: '
                                     '{}'.format(request.cert_type))
                data = rel.to_publish.get(publish_key.format(unit_name), {})
                if request.common_name in data:
                    self.responses[request.request_id] = Certificate(
                        request_id=request.request_id,
                        cert_type=request.cert_type,
                        common_name=request.common_name,
                        cert=data['cert'],
                        key=data['key'],
                    )

    def set_root_ca_cert(self, cert):
        for relation in self.endpoint.relations:
            # All the clients get the same CA, so send it to them.
            relation.to_publish_raw['ca'] = cert

    def set_root_ca_chain(self, chain):
        for relation in self.endpoint.relations:
            # All the clients get the same chain, so send it to them.
            relation.to_publish_raw['chain'] = chain

    def set_global_client_cert(self, cert, key):
        for relation in self.endpoint.relations:
            relation.to_publish_raw.update({
                'client.cert': cert,
                'client.key': key,
            })

    def set_cert(self, request, cert, key):
        rel = request.relation
        unit_name = request.unit.unit_name.replace('/', '_')
        if request._is_top_level_server_cert_request:
            # backwards compatibility; if this is the cert that was requested
            # as a single server cert, set it in the response as the single
            # server cert
            rel.to_publish_raw.update({
                '{}.server.cert'.format(unit_name): cert,
                '{}.server.key'.format(unit_name): key,
            })
        else:
            if request.cert_type == 'server':
                publish_key = '{}.processed_requests'
            elif request.cert_type == 'client':
                publish_key = '{}.processed_client_requests'
            else:
                raise ValueError('Unknown cert_type: '
                                 '{}'.format(request.cert_type))
            data = rel.to_publish.get(publish_key.format(unit_name), {})
            data[request.common_name] = {
                'cert': cert,
                'key': key,
            }
            # have to explicit store to ensure serialized data is updated
            rel.to_publish[publish_key] = data
        # add this cert to the cache of responses
        self.responses[request.request_id] = Certificate(
            request_id=request.request_id,
            cert_type=request.cert_type,
            common_name=request.common_name,
            cert=cert,
            key=key,
        )

    def clear(self):
        rel = self.relation
        rel.to_publish_raw.update({
            'ca': None,
            'chain': None,
            'client.cert': None,
            'client.key': None,
        })
        for unit in rel.joined_units:
            unit_name = unit.unit_name.replace('/', '_')
            rel.to_publish_raw.update({
                '{}.server.cert'.format(unit_name): None,
                '{}.server.key'.format(unit_name): None,
            })
            rel.to_publish.update({
                '{}.processed_requests'.format(unit_name): None,
                '{}.processed_client_requests'.format(unit_name): None,
            })
