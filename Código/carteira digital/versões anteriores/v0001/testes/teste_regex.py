import re

while(True):
	texto = input("insira seu PIN:\n")
	if re.match(r"^\d{4}$", texto):
		print('PIN válido')
	else:
		print('PIN inválido')
