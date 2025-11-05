# SIEM Security Project

## 📦 Dipendenze

```
Flask==3.0.0
Flask-Login==0.6.3
Flask-SQLAlchemy==3.1.1
Flask-Bcrypt==1.0.1
```

## 🚀 Installazione

### 1. Clona il repository
```bash
git clone https://github.com/dsiv57/PWGroup3
cd PWGroup3
```

### 2. Crea e attiva l'ambiente virtuale

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Installa le dipendenze
```bash
pip install -r requirements.txt
```

### 4. Avvia l'applicazione
```bash
python app.py
```

> Il database viene creato automaticamente al primo avvio con l'account admin già inserito di default.

### 5. Accedi all'app

Apri il browser su: **http://127.0.0.1:5000**

**Credenziali admin:**
- Username: `admin`
- Password: `Admin123!`

Oppure registra un nuovo account dalla pagina `/register`
