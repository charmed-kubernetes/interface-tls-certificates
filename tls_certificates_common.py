from charms.reactive import is_data_changed, data_changed, clear_flag


class CertificateRequest(dict):
    def __init__(self, request_id, cert_type, cert_name, common_name, sans,
                 unit, protocol):
        self._unit = unit
        self._protocol = protocol
        super().__init__({
            'request_id': request_id,
            'cert_type': cert_type,
            'cert_name': cert_name,
            'common_name': common_name,
            'sans': sans,
        })

    def __missing__(self, key):
        if key == 'certificate_name':
            return self.cert_name
        else:
            raise KeyError(key)

    @property
    def unit(self):
        return self._unit

    @property
    def relation(self):
        return self.unit.relation

    @property
    def request_id(self):
        return self['request_id']

    @property
    def cert_type(self):
        """
        Type of certificate, 'server' or 'client', being requested.
        """
        return self['cert_type']

    @property
    def cert_name(self):
        """
        Deprecated.  An optional name used to identify the certificate.

        Use `request_id` instead to unambiguously identify the certificate.
        """
        return self['cert_name']

    @property
    def common_name(self):
        return self['common_name']

    @property
    def sans(self):
        return self['sans']

    @property
    def cert(self):
        """
        The cert published for this request, if any.
        """
        return self._protocol.responses.get(self.request_id)

    @property
    def is_handled(self):
        has_cert = self.cert is not None
        same_sans = not is_data_changed(self.request_id, self.sans)
        return has_cert and same_sans

    def set_cert(self, cert, key):
        self._protocol.set_cert(self, cert, key)
        data_changed(self.request_id, self.sans)
        # update the endpoint's flags to reflect our change in state
        if not self.relation.endpoint.new_server_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.server.certs.requested'))
            # deprecated legacy flag
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.server.cert.requested'))
        if not self.relation.endpoint.new_client_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.client.certs.requested'))
            # deprecated legacy flag
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.client.cert.requested'))
        if not self.relation.endpoint.new_requests:
            clear_flag(self.relation.endpoint.expand_name(
                '{endpoint_name}.certs.requested'))


class Certificate(dict):
    """
    Represents a created certificate and key.

    The ``cert_type``, ``common_name``, ``cert``, and ``key`` values can
    be accessed either as properties or as the contents of the dict.
    """
    def __init__(self, request_id, cert_type, common_name, cert, key):
        super().__init__({
            'request_id': request_id,
            'cert_type': cert_type,
            'common_name': common_name,
            'cert': cert,
            'key': key,
        })

    @property
    def request_id(self):
        return self['request_id']

    @property
    def cert_type(self):
        return self['cert_type']

    @property
    def common_name(self):
        return self['common_name']

    @property
    def cert(self):
        return self['cert']

    @property
    def key(self):
        return self['key']


class VersionedProtocol:
    VERSION = None
    """
    Integer version number for this implementation.

    Must be set by subclasses.
    """

    @classmethod
    def negotiate(cls, relation):
        """
        Given a relation instance, return the correct implementation for
        the maximum mutually supported version.

        If the relation is currently using an older protocol version than
        is mutually supported, this will call `upgrade_protocol` on the
        new version, followed by `clear` on the old version.
        """
        subclasses = {sub.VERSION: sub for sub in cls.__subclasses__()}
        if None in subclasses:
            raise ValueError('Protocol implementation missing version number: '
                             '{}'.format(subclasses[None].__name__))
        local_min_version = min(subclasses.keys())
        local_max_version = max(subclasses.keys())
        remote_max_version = (relation.joined_units.received['max-version'] or
                              local_min_version)
        current_version = (relation.to_publish['current-version'] or
                           local_min_version)
        new_version = min(local_max_version, remote_max_version)
        relation.to_publish['max-version'] = local_max_version
        if current_version != new_version:
            old_protocol = subclasses[current_version](relation)
            new_protocol = subclasses[new_version](relation)
            new_protocol.upgrade_from(old_protocol)
            old_protocol.clear()
        return subclasses[new_version](relation)

    def __init__(self, relation):
        self.relation = relation

    @property
    def endpoint(self):
        return self.relation.endpoint

    def upgrade_protocol(self, old_protocol):
        """
        Upgrade to this protocol version from a previous one.

        Must be implemented by subclasses.
        """
        raise NotImplementedError()

    def clear(self):
        """
        Clear all data in this protocol version's format from the relation.

        Called automatically once the protocol has been upgraded.

        Should be implemented by subclasses.
        """
        pass
