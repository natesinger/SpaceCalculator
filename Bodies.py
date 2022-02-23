from dataclasses import dataclass
from typing import Optional

### TODO: Check this periodically because these numbers get updated. ###
# All units are in kilometers, seconds, or degrees unless otherwise stated.

@dataclass
class Body():
    """Base class for any celestial body or parent class of satellites.
    
     #### Attributes:
        - name (str): Name of body.
        - parent (Body): Orbited body or None.
        - mass (float): Mass in kilograms.
        - k (float): Gravitational constant in meters cubed per seconds squared.
        - r (float): Equatorial radius in meters. 
        - rotationPeriod (float) time in Earth days for the body to complete one sidereal rotation
        - orbitalPeriod (float) time in Earth days for the body to complete one sidereal orbit"""

    name: str
    parent: Optional["Body"]
    mass: float
    k: float
    r: float
    rotationPeriod: float
    orbitalPeriod: float

Sun = Body(
    name="Sun",
    parent=None,
    mass=1.989e30,
    k=1.32712442099e20,
    r=6.95700e8,
    rotationPeriod=25.38,
    orbitalPeriod=None
)

Earth = Body(
    name="Earth",
    parent=Sun,
    mass=5.9722e24,
    k=3.986004e14,
    r=6.3781e6,
    rotationPeriod=0.9972698,
    orbitalPeriod=365.256
)

Moon = Body(
    name="Moon",
    parent=Earth,
    mass=0.07346e24,
    k=4.90279981e12,
    r=1.7381e6,
    rotationPeriod=27.321661,
    orbitalPeriod=27.321661 
)