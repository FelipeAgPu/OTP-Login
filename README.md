# OTP Login Implementation (ECI Login)

This project will give you an example of a login page that implements a 2FA using an OTP send by email to the users.

## Getting started

### Installing

First, you got to clone this repository with the following command:

```
git clone https://github.com/FelipeAgPu/OTP-Login.git
```

### Prerequisites

To run this project you must have Python installed in your computer, at least the version 3

You can check your Python version typing on cmd:

```
python --version
```

### Using the Virtual Environment

The best and easiest way for running the project is in a virtual environment.

To create a virtual environment you have to run this command in the project directory:

```
py -m venv venv
```

**Activate**:

```python
cd venv/Scripts
activate
```

**Deactivate**:

```python
cd venv/Scripts
deactivate
```

Install requirements:

- With the **venv** activated:

```python
pip install -r requirements.txt
```

### Running

Once you have installed all the requirements in the **venv** if you want to run the server you just have to run:

```
py run main.py
```

Now you can go to: http://localhost:5000

There you will be using the project so you can create an user and log in with that user.

---

## Developed by

This login was first created by [Faouzizi](https://github.com/Faouzizi) then there were some modifications and the otp validation part was added by:

- Juan Felipe Aguas Pulido
- Diego Fernando Ruiz Rojas
- Juan Sebastián Cadavid Peralta

Students from Escuela Colombiana de Ingeniería Julio Garavito
