# ABC = Abstract Base Class, allows us to create abstract classes in Python
# abstractmethod = decorator that forces child classes to implement a method
from abc import ABC, abstractmethod

# Used to record the exact time when the input object is created
from datetime import datetime

# BaseInput is abstract — it can never be instantiated directly
# It defines the common structure for all input types (email, URL, etc.)
class BaseInput(ABC):

    def __init__(self, content: str):
        # The raw text content of the input (email body or URL string)
        self.content = content
        
        # Automatically record when this input was created
        self.timestamp = datetime.now()

    # This method MUST be implemented in every child class
    # Each input type validates differently, so we leave the logic to the child
    @abstractmethod
    def validate(self) -> bool:
        pass    