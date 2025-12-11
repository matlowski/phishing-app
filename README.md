# phishing-app

tutaj daj jakiś obrazek

Aby uruchomić środowisko projektowe należy mieć na swojej maszynie zainstalowane zintegrowane środowisko programistyczne (np. PyCharm) lub edytor kodu (np. Visual Studio Code) i następnie:
1. Zainstalować na swojej maszynie lokalnej najnowszą wersję pythona. Można to zrobić pobierając go z oficjalnej strony: https://www.python.org/ .
2. Następnym krokiem jest utowrzenie nowego folderu oraz wejście do niego: 

   $ mkdir new_folder 

   $ cd new_folder
    
4. W owym folderze należy utworzyć środowisko wirtualne:
   
   $ python -m venv venv
   
5. Kolejnym krokiem jest uaktywnienie środowiska wirtualnego, które może różnić się w zależności od systemu operacyjnego zainstalowanego na maszynie. Rozwiązania dla każdego systemu operacyjnego można znaleźć pod linkiem: https://docs.python.org/3/library/venv.html#how-venvs-work
6. Następnie należy zainstalować wszystkie pakiety zdefiniowane w pliku requirements.txt:

   $ pip install -r requirements.txt

7. Utworzyć darmowe konta w serwisach Virustotal: https://www.virustotal.com/gui/home/upload oraz abuseipdb: https://www.abuseipdb.com/ w celu wygenerowania kluczy API, które następnie należy umieścić w wyznaczonym miejscu w kodzie w pliku 'views.py'. 

8. Uruchomić serwer lokalny poleceniem:
   
   $ python manage.py runserver

10. W celu odwiedzenia strony wkleić w przeglądarce link: http://127.0.0.1:8000/
