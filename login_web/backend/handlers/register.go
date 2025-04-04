package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"login/models" // Ajusta este import según tu estructura de carpetas

	_ "github.com/mattn/go-sqlite3" // Import side effect para SQLite driver
	"golang.org/x/crypto/bcrypt"
)

// PostRegisterHandler maneja el registro de nuevos usuarios
func PostRegisterHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Decodificar cuerpo del request
		var req models.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error al decodificar el cuerpo del request: %v", err)
			http.Error(w, `{"error":"Cuerpo inválido"}`, http.StatusBadRequest)
			return
		}

		// 2. Validación básica
		if req.Username == "" || req.Password == "" {
			http.Error(w, `{"error":"Usuario y contraseña requeridos"}`, http.StatusBadRequest)
			return
		}

		// 3. Encriptar contraseña
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error al encriptar la contraseña: %v", err)
			http.Error(w, `{"error":"Error interno del servidor"}`, http.StatusInternalServerError)
			return
		}

		// 4. Insertar usuario en la base de datos
		result, err := db.ExecContext(r.Context(),
			"INSERT INTO users(username, password_hash) VALUES (?, ?)",
			req.Username, string(hashedPassword),
		)
		if err != nil {
			// Verifica si es un error de restricción UNIQUE
			if sqliteErr, ok := err.(interface{ Error() string }); ok &&
				contains(sqliteErr.Error(), "UNIQUE constraint failed") {
				http.Error(w, `{"error":"El nombre de usuario ya está en uso"}`, http.StatusConflict)
				return
			}
			log.Printf("Error al insertar usuario: %v", err)
			http.Error(w, `{"error":"Error al registrar el usuario"}`, http.StatusInternalServerError)
			return
		}

		// 5. Obtener ID del nuevo usuario
		userID, err := result.LastInsertId()
		if err != nil {
			log.Printf("Error al obtener el ID del usuario registrado: %v", err)
			http.Error(w, `{"error":"Usuario registrado, pero sin ID"}`, http.StatusInternalServerError)
			return
		}

		// 6. Respuesta exitosa
		response := models.NewSuccessResponse(models.RegisterSuccessData{
			UserID:   userID,
			Username: req.Username,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}
}

// contains verifica si un string está contenido en otro
func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) > 0 && (len(haystack) >= len(needle)) && (string(haystack[:len(needle)]) == needle || contains(haystack[1:], needle))
}
