"""Device double used by config-driven dispatch tests."""


class FakeDeviceClient:
    instances = []

    def __init__(self, host, router_info):
        self.host = host
        self.router_info = router_info
        self.cleaned_up = False
        self.instances.append(self)

    def get_config(self):
        return "<config/>"

    def cleanup(self):
        self.cleaned_up = True
