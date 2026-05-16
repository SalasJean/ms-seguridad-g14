INSERT INTO rol (nombre_rol)
SELECT 'USER'
    WHERE NOT EXISTS (
    SELECT 1 FROM rol WHERE nombre_rol = 'USER'
);

INSERT INTO rol (nombre_rol)
SELECT 'ADMIN'
    WHERE NOT EXISTS (
    SELECT 1 FROM rol WHERE nombre_rol = 'ADMIN'
);