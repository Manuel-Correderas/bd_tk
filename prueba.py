from backend import SessionLocal, Person

db = SessionLocal()
print(db.query(Person).count())