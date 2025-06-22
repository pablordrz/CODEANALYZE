from passlib.hash import bcrypt

# Escribe aquí la contraseña en texto plano
password_plano = "usuario"

# Genera el hash
hash_generado = bcrypt.hash(password_plano)

print("Hash para guardar en la base de datos:")
print(hash_generado)