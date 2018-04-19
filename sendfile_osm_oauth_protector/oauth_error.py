class OAuthError(Exception):
    def __init__(self, message, error_response):
        super(Exception, self).__init__(message)
        self.error_message = error_response
