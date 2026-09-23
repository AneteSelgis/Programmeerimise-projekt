from tinydb import TinyDB, Query

db = TinyDB('db.json')
Users = Query()

def register():
    username = input("Loo kasutajanimi: ")
    password = input("Loo parool: ")

    db.insert({"username": username, "password": password, "data": {}})
    print("Konto loodud!")

def login():
    username = input("Kasutajanimi: ")
    password = input("Parool: ")

    user = db.search(Users.username == username)
    if not user:
        print("Kasutajat ei ole!")
        return None
    
    user = user[0]

    if user["password"] == password:
        print("Sisselogimine õnnestus!")
        return user
    else:
        print("Vale parool!")
        return None

def user_dashboard(user):
    print(f"\nTere, {user['username']}!")
    print("See on sinu personaalne ala.")

    while True:
        print("\nValikud:")
        print("1. Vaata oma andmeid")
        print("2. Lisa personaalne info")
        print("3. Logi välja")

        choice = input("Valik: ")

        if choice == "1":
            print("Sinu andmed:", user["data"])

        elif choice == "2":
            key = input("Sisesta teema nimi: ")
            value = input("Sisesta teema väärtus: ")

            user["data"][key] = value
            db.update({"data": user["data"]}, Users.username == user["username"])
            print("Lisatud!")

        elif choice == "3":
            print("Logitud välja.")
            break

        else:
            print("Tundmatu valik.")

def main():
    while True:
        print("\n--- MENÜÜ ---")
        print("1. Registreeri")
        print("2. Logi sisse")
        print("3. Välju")

        choice = input("Valik: ")

        if choice == "1":
            register()

        elif choice == "2":
            user = login()
            if user:
                user_dashboard(user)

        elif choice == "3":
            print("Programmi lõpetamine.")
            break

        else:
            print("Tundmatu valik.")

main()
