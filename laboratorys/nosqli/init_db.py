import os
from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://nosqli-mongo:27017")
DB_NAME = "nosqli_lab"

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

db.users.drop()
db.users.insert_many([
    {"username": "admin", "password": "S3cr3t_Adm1n_2026",
     "secret": "NSU{nosqli_master}", "role": "admin"},
    {"username": "user1", "password": "qwerty",
     "secret": "nothing", "role": "user"},
    {"username": "user2", "password": "12345",
     "secret": "nothing", "role": "user"},
])

db.products.drop()
db.products.insert_many([
    {"name": "laptop", "price": 1000, "hidden": False},
    {"name": "phone",  "price": 500,  "hidden": False},
    {"name": "flag",   "price": 0,    "hidden": True,
     "secret": "NSU{nosqli_where_rce}"},
])

print(f"[init_db] users={db.users.count_documents({})} "
      f"products={db.products.count_documents({})}")
