#!/bin/bash

# Активируем виртуальное окружение, если оно есть
if [ -f "venv/bin/activate" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Virtual environment not found, skipping activation."
fi

# Запускаем Flask-приложение с помощью python
echo "Starting Flask app..."
python app.py
