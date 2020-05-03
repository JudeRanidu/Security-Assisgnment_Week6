import configparser
import getpass
from passlib.hash import md5_crypt

def register():
    config_parser = configparser.ConfigParser()
    while True:
        username = input("New username: ").strip()
        print("Select User Type: ")
        print("1-staff\n2-patient")
        user_type = input("Your input:")
        if user_type == "2":
            user_type = "patient"
            privilege_level = "level_0"
            username = username + " " + "patient"
            config_parser.read('config.ini')
            sections = config_parser.sections()
            if username in sections:
                print("Username already taken")
                continue
            break
        elif user_type == "1":
            username = username + " " + "staff"
            config_parser.read('config.ini')
            sections = config_parser.sections()
            if username in sections:
                print("Username already taken")
                continue
            print("select staff type")
            print("1-doctor\n2-nurse\n3-lab\n4-reception\n5-pharmacy")
            staff_types = ["doctor","nurse","lab","reception","pharmacy"]
            while True:
                staff_type = input("Your input:")
                user_type = staff_types[int(staff_type)-1]
                if staff_type == "1":
                    code = input("Enter Verification Code:")
                    if code == "doc1010":
                        privilege_level = "level_1"
                        break
                    else:
                        print("Wrong Verification Code")
                        continue
                elif staff_type == "2":
                    code = input("Enter Verification Code:")
                    if code == "nur2000":
                        privilege_level = "level_2"
                        break
                    else:
                        print("Wrong Verification Code")
                        continue
                elif staff_type == "3":
                    code = input("Enter Verification Code:")
                    if code == "lab3003":
                        privilege_level = "level_3"
                        break
                    else:
                        print("Wrong Verification Code")
                        continue
                elif staff_type == "4":
                    code = input("Enter Verification Code:")
                    if code == "rec4044":
                        privilege_level = "level_4"
                        break
                    else:
                        print("Wrong Verification Code")
                        continue
                elif staff_type == "5":
                    code = input("Enter Verification Code:")
                    if code == "pha5555":
                        privilege_level = "level_5"
                        break
                    else:
                        print("Wrong Verification Code")
                        continue
                else:
                    print("Wrong input..Please check again")
                    continue
            break
        else:
            print("Wrong input..Please check again")
            continue
    while True:
        password = getpass.getpass(prompt="New password: ")
        if not len(password) > 0:
            print("Empty password not accepted")
            continue
        else:
            confirm_password = getpass.getpass(prompt="Confirm Password: ")
            if (password == confirm_password):
                print("Passwords Matched...")
                break
            else:
                print("Not Matching.Please Re-enter...")
                continue
    hashed_password = md5_crypt.hash(password)
    config_parser = configparser.ConfigParser()
    config_parser[username] = {"password": hashed_password,
                               "user_type": user_type,
                               "privilege_level": privilege_level}
    config_file = open('config.ini','a')                           
    config_parser.write(config_file)
    config_file.close()
    print("Registration Successful")


def login():
    while True:
        username = input("Username: ")
        print("Enter User Type: ")
        print("1-staff\n2-patient")
        user_type = input("Your input:")
        if (user_type == '1') or (user_type == '2'):
            if(user_type == '1'):
                username = username + " staff"
            if(user_type == '2'):
                username = username + " patient"
            config_parser = configparser.ConfigParser()
            config_parser.read('config.ini')
            sections = config_parser.sections()
            if(username in sections):
                print("***user verfied***")
                while True:
                    password = getpass.getpass(prompt="Password: ")
                    hashed_password = config_parser.get(username, 'password')
                    if md5_crypt.verify(password, hashed_password):
                        print("***password verified***")
                        session(username)
                        break
                    else:
                        print("***password is incorrect***")
                        continue
                break
            else:
                print("invalid username or user type")
                continue
        else:
            print("Wrong input..Please check again")
            continue


def editSession(patient_name, pl):
    config_parser = configparser.ConfigParser()
    config_parser.read('data.ini')
    while True:
        print("Select a section to Edit: \n 1.personal details \n 2.sickness details \n 3.drug prescriptions \n 4.lab test prespriptions \n 5.back/done")
        option = input("Your input:")
        if option == '1':
            if (pl == "level_4"):
                details_old = config_parser.get(patient_name, 'personal_details')
                print('Old Record: ', details_old)
                print("Enter New Details:")
                details_new = input('Your input:').strip()
                mode = input("Do you want to keep old records (Y/N): ")
                while True:
                    if (mode == 'y' or mode == 'Y'):
                        details = details_old + ', ' + details_new
                        break
                    elif (mode == 'n' or mode == 'N'):
                        details = details_new
                        break
                    else:
                        print("(Y/N)??")
                        continue
                config_parser.set(patient_name, 'personal_details', details)
                print(config_parser.get(patient_name, 'personal_details'))
                print('Updated Successfully')
            else:
                print('No access to edit this section')
        elif option == '2':
            if (pl == "level_1"):
                details_old = config_parser.get(patient_name, 'sickness_details')
                print('Old Record: ', details_old)
                print("Enter New Details:")
                details_new = input('Your input:').strip()
                mode = input("Do you want to keep old records (Y/N): ")
                while True:
                    if (mode == 'y' or mode == 'Y'):
                        details = details_old + ', ' + details_new
                        break
                    elif (mode == 'n' or mode == 'N'):
                        details = details_new
                        break
                    else:
                        print("(Y/N)??")
                        continue
                config_parser.set(patient_name, 'sickness_details', details)
                print(config_parser.get(patient_name, 'sickness_details'))
                print('Updated Successfully')
            else:
                print('No access to edit this section')
        elif option == '3':
            if (pl == "level_1" or pl == "level_2" or pl == "level_5"):
                details_old = config_parser.get(patient_name, 'drug_prescription')
                print('Old Record: ', details_old)
                print("Enter New Details:")
                details_new = input('Your input:').strip()
                mode = input("Do you want to keep old records (Y/N): ")
                while True:
                    if (mode == 'y' or mode == 'Y'):
                        details = details_old + ', ' + details_new
                        break
                    elif (mode == 'n' or mode == 'N'):
                        details = details_new
                        break
                    else:
                        print("(Y/N)??")
                        continue
                config_parser.set(patient_name, 'drug_prescription', details)
                print(config_parser.get(patient_name, 'drug_prescription'))
                print('Updated Successfully')
            else:
                print('No access to edit this section')
        elif option == '4':
            if (pl == "level_1" or pl == "level_2" or pl == "level_3"):
                details_old = config_parser.get(patient_name, 'lab_test_prescription')
                print('Old Record: ', details_old)
                print("Enter New Details:")
                details_new = input('Your input:').strip()
                mode = input("Do you want to keep old records (Y/N): ")
                while True:
                    if (mode == 'y' or mode == 'Y'):
                        details = details_old + ', ' + details_new
                        break
                    elif (mode == 'n' or mode == 'N'):
                        details = details_new
                        break
                    else:
                        print("(Y/N)??")
                        continue
                config_parser.set(patient_name, 'lab_test_prescription', details)
                print(config_parser.get(patient_name, 'lab_test_prescription'))
                print('Updated Successfully')
            else:
                print('No access to edit this section')
        elif option == '5':
            break
    config_parser.write(open('data.ini', 'w'))


def viewSession(patient_name, pl):
    config_parser = configparser.ConfigParser()
    config_parser.read('data.ini')
    while True:
        print("View Options: \n 1-personal details \n 2-sickness details \n 3-drug prescriptions \n 4-lab test prespriptions \n 5-back")
        option = input("Your input:")
        if option == '1':
            print(config_parser.get(patient_name, "personal_details"))
            continue
        elif option == '2':
            print(config_parser.get(patient_name, "sickness_details"))   
            continue
        elif option == '3':
            if (pl=='level_0' or pl=='level_1' or pl=='level_2'or pl=='level_4' or pl=='level_5'):
                print(config_parser.get(patient_name, "drug_prescription"))
            else:
                print('No access to this section')
            continue
        elif option == '4':
            if (pl=='level_0' or pl=='level_1' or pl=='level_2' or pl=='level_3'or pl=='level_4'):
                print(config_parser.get(patient_name, "lab_test_prescription"))
            else:
                print('No access to this section')
            continue
        elif option == '5':
            break


def staffSession(privilege_level):
    while True:
        print("Options: \n 1.view or edit patient details \n 2.logout")
        option = input("Your input:")
        if option == "2":
            print("Logging out...")
            break
        elif option == "1":
            patient_name = input("Enter patient name: ")
            patient_name = patient_name + " " + "patient"
            config_parser = configparser.ConfigParser()
            config_parser.read('data.ini')
            sections = config_parser.sections()
            if(patient_name in sections):
                print("options: \n 1.view details \n 2.edit details")
                option = input('Your input:')
                if option == '1':
                    viewSession(patient_name, privilege_level)
                elif option == '2':
                    editSession(patient_name, privilege_level)
            else:
                print("No Records")
        else:
            print("Wrong input..Please check again")
            continue


def patientSession(username):
    while True:
        print("Options: \n 1.view history \n 2.logout")
        option = input("Your input:")
        if option == "2":
            print("Logging out...")
            break
        elif option == "1":
            config_parser = configparser.ConfigParser()
            config_parser.read('data.ini')
            sections = config_parser.sections()
            if(username in sections):
                viewSession(username,'level_0')
            else:
                print("No Records")
        else:
            print("Wrong input..Please check again")


def session(username):
    print("Welcome to your account ")
    config_parser = configparser.ConfigParser()
    config_parser.read('config.ini')
    privilege_level = config_parser.get(username, "privilege_level")
    if privilege_level == 'level_0':
        patientSession(username)
    else:
        staffSession(privilege_level)

print("Select the number related to the functionality")
while True:
    print("1-register\n2-login\n3-exit")
    option = input("Your input:")
    if option == "1":
        register()
    elif option == "2":
        login()
    elif option == "3":
        break
    else:
        print("Wrong input..Please check again")
