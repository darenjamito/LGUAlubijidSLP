from app import app, db, create_tables_and_admin

# Create all database tables and initialize data
create_tables_and_admin()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)