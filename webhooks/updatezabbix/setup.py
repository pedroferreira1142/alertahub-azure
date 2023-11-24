from setuptools import find_packages, setup

version = '5.0.2'

setup(
    name='alerta-update-zabbix',
    version=version,
    description='Zabbix webhook',
    url='https://github.com/alerta/alerta-contrib',
    license='MIT',
    author='Pedro Ferreira',
    author_email='pedro.d.ferreira@pt.clara.net',
    packages=find_packages(),
    py_modules=['alerta_updatezabbix'],
    install_requires=[
        'python-dateutil'
    ],
    include_package_data=True,
    zip_safe=True,
    entry_points={
        'alerta.webhooks': [
            'updatezabbix = alerta_updatezabbix:UpdateZabbixWebhook'
        ]
    }
)
