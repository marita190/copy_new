#!/bin/sh
set -e

until python -c "
import pymongo, sys
try:
    pymongo.MongoClient('mongodb://nosqli-mongo:27017', serverSelectionTimeoutMS=2000).admin.command('ping')
    sys.exit(0)
except Exception:
    sys.exit(1)
" >/dev/null 2>&1; do
  echo "waiting for mongodb..."
  sleep 1
done

python init_db.py

exec python app.py
