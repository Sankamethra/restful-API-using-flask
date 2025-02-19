# database.py
from pymongo import MongoClient
from config import Config
import certifi

# Use this connection string format
client = MongoClient(
    Config.MONGODB_URI,
    tls=True,
    tlsCAFile=certifi.where()
)
db = client['template_db']