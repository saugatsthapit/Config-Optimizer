from databases import Database
import os

username = os.getenv('DB_USERNAME', 'default_username')  
password = os.getenv('DB_PASSWORD', 'default_password') 
db_name = os.getenv('DB_NAME', 'default_db')  

DATABASE_URL = f"mysql://{username}:{password}@localhost/{db_name}"
database = Database(DATABASE_URL)
