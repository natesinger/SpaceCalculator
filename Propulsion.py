class Propulsion:
    """Default Constructor"""                                                  
    def __init__(self, thrust=0.0, fuel=0.0, isp=0.0):                                                        # Default values so we can create a satellite in an orbit where we don't care about propulsion
        self.thrust = thrust
        self.fuel = fuel
        self.isp = isp