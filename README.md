# Django JWT Authentication with Email Confirmation

<!-- [![Build Status](https://travis-ci.org/your-username/your-repository.svg?branch=master)](https://travis-ci.org/your-username/your-repository) -->

This repository contains a Django project implementing JWT (JSON Web Token) authentication with email confirmation service using Django Rest Framework.

## Features

- User registration with email confirmation
- User login and JWT generation
- JWT authentication for protected endpoints
- Email confirmation link with token expiration
- Password reset functionality via email

## Requirements

- Python 3.x
- Django 3.x
- Django Rest Framework 3.x

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/your-repository.git
cd your-repository
```


2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Configure the database settings in settings.py.

5. Apply the migrations:

```bash
python manage.py migrate
```

6. Run the development server:

```bash
python manage.py runserver
```

## Usage
Access the API documentation at `{API_URL}/swagger/` or `{API_URL}/redoc/`.

## Configuration
- Email settings can be configured in `settings.py`.
- JWT settings can be configured in `settings.py`.

## Testing
To run the tests, execute the following command:

```bash
python manage.py test
```