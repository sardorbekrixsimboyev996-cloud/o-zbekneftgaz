import getpass,re,sqlite3
from main import initialize, db, password_hash
initialize()
nickname=input('Administrator login: ').strip().lower()
if not re.fullmatch(r'[a-z0-9_.-]{3,50}',nickname): raise SystemExit('Login: 3–50 lotin harfi, raqam, _ . -')
name=input('Ism: ').strip() or nickname
password=getpass.getpass('Parol (kamida 10 belgi): ')
if len(password)<10 or len(password)>128: raise SystemExit('Parol 10–128 belgi bo‘lsin.')
if password!=getpass.getpass('Parolni takrorlang: '): raise SystemExit('Parollar mos emas.')
try:
    with db() as c: c.execute('INSERT INTO users(nickname,name,password,role) VALUES(?,?,?,?)',(nickname,name,password_hash(password),'admin'))
except sqlite3.IntegrityError: raise SystemExit('Bu login mavjud. Boshqa login tanlang.')
print('Administrator yaratildi.')
