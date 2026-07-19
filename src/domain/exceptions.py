class SecurityPlatformException(Exception):
    """
    Eccezione base per la piattaforma di Security Cloud.
    """

    pass


class InvalidFindingException(SecurityPlatformException):
    """
    Sollevata quando un finding non supera la convalida formale o di schema.
    """

    pass


class PluginLoadException(SecurityPlatformException):
    """
    Sollevata quando si verifica un errore durante il caricamento dinamico di un plugin.
    """

    pass
