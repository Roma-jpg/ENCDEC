# ENCDEC

## Описание

**ENCDEC** - это инструмент командной строки для шифрования и расшифровки файлов или папок с использованием симметричного ключа шифрования Fernet. Это простой и надежный способ защиты конфиденциальных данных.

## Возможности
- Шифруйте и расшифровывайте отдельные файлы.
- Шифровать и расшифровывать целые папки.
- Укажите режим шифрования или дешифрования.
- Автоматически генерировать и сохранять новый ключ шифрования или использовать существующий.
- Укажите расширения файлов для шифрования или расшифровки.

## Установка

```
# Клонируйте репозиторий 
git clone https://github.com/Roma-jpg/ENCDEC.git

# Перейдите в каталог проекта
cd ENCDEC

# Установите зависимости
pip install -r requirements.txt

# Выведите help команду
python encdec_tool.py --help
```
Вывод:

```
usage: encdec_tool.py [-h] [-m {enc,dec}] [-k KEY] [-e EXTENSIONS [EXTENSIONS ...]] path {enc,dec} key

Encrypt or decrypt a file or folder using Fernet encryption.

positional arguments:
  path                  Input file or folder path
  {enc,dec}             Encryption mode: "enc" or "dec"
  key                   Key file path

options:
  -h, --help            show this help message and exit
  -m {enc,dec}, --mode {enc,dec}
                        Encryption mode: "enc" or "dec"
  -k KEY, --key KEY     Key file path
  -e EXTENSIONS [EXTENSIONS ...], --extensions EXTENSIONS [EXTENSIONS ...]
                        List of file extensions to encrypt

```

## Использование

##### Шифрование одного файла:
 
```
python encdec_tool.py -f "path/to/file.ext" -m enc
```

Это не только закриптует сам файл, но ещё создаст файл "keyfile.key". В нём содержится ключ, для дешифровки ваших файлов. Не потеряйте его и сохрание в надёжном месте.
Обратите внимание, что это работает только в первый раз. В последующие разы выам придётся указывать параметр --key всегда, чтобы не потерять свои файлы.

##### Дешифрование одного файла:
 
```
python encdec_tool.py -f "path/to/file.ext" -m dec -k keyfile.key
```

Обратите внимание, что при дешифрации мы всегда указываем keyfile с помощью которого  мы закриптовали файл. Без этого дешифровка не пройдёт, либо навсегда повредит файл. Будьте осторожны.
Также обратите внимание, что здесь "enc" поменялось на "dec".
Что означает "encrypt" и "decrypt" соответственно.

##### Шифрование папки
 
```
python encdec_tool.py -f ./test_folder/ -m enc -k keyfile.key
```
В этом случае, мы шифруем абсолютно все файлы в заданной папке используя ключ из keyfile.key. Все файлы будут зашифрованы этим ключом.
Заметьте, что программа шифрует файлы рекурсивно, поэтому файлы в папках тоже будут зашифрованы.

##### Дешифрование папки
 
```
python encdec_tool.py -f ./test_folder/ -m dec -k keyfile.key
```

Здесь же мы делаем всё наоборот. Мы используя ключ из файла расшифровываем все файлы в папке. По выполению программы все файлы будут расшифрованы.

##### Фильтрация файлов

Предположим вам нужно зашифровать все видео в папке. Но не трогать остальные файлы. Тогда воспользуйтесь фильтром расширений.

```
python encdec_tool.py -f ./test_folder/ -m enc -k keyfile.key -e .mp4 .mkv
```

Добавляя "-e .mp4 .mkv" вы говорите программе шифровать только файлы с расширением .mp4 и .mkv

### Заключение:
С помощью этого инструмента вы можете защитить свои файлы. Либо чужие, тут решайте сами, но автор ни в чём не причастен если с помощью моей программы чьи либо файлы пострадают. 

### Лицензия: MIT
