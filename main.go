package main
import (
	"fmt"
    "github.com/gin-gonic/gin"
    "github.com/gin-contrib/cors"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "net/http"
    "github.com/golang-jwt/jwt/v4"
    "time"
)
var jwtSecret = []byte("your_secret_key")
type User struct {
    ID       uint   `json:"id" gorm:"primaryKey"`
    Email    string `json:"email" gorm:"unique"`
    Password string `json:"password"`
}
type Task struct {
    ID       uint   `json:"id" gorm:"primaryKey"`
    TaskName string `json:"taskname"`
    TaskTime string `json:"tasktime"`
}
var db *gorm.DB

func initDB() {
    var err error
     dsn := "postgresql://neondb_owner:r6kP2wJuElTC@ep-lingering-meadow-a11exwte.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
    db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        panic("failed to connect to database")
    }
	fmt.Println("Database connected successfully!")     
	db.AutoMigrate(&User{},&Task{})
}
func generateToken(userID uint) string {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(time.Hour * 24).Unix(),
    })
    tokenString, _ := token.SignedString(jwtSecret)
    return tokenString
}


func main() {
    router := gin.Default()
    router.Use(cors.Default())
    initDB()
    setupRoutes(router)
    router.Run(":8080")
}

func setupRoutes(router *gin.Engine) {
    router.POST("/tasks", createTask)
    router.POST("/login",loginUser)
    router.POST("/register",registerUser)
    router.GET("/tasks", getTasks)
}
func registerUser(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    fmt.Println("The password is",user.Password);
    // hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    // if err != nil {
    //     c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
    //     return
    // }
    // user.Password = string(hashedPassword)

    if err := db.Create(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
        return
    }
    c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully!"})
}

func loginUser(c *gin.Context) {
    var credentials struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    
    if err := c.ShouldBindJSON(&credentials); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    fmt.Println("Attempting to log in with email:", credentials.Email)
    var user User
    if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
        fmt.Println("User not found:", err)
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }
    // hashedPassword,err := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
    // if err != nil {
    //     c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
    //     return
    // }
    // credentials.Password = string(hashedPassword)
    // fmt.Println("the hashed password is",credentials.Password);
    // fmt.Println("Found user:", user)

    if user.Password != credentials.Password {
        fmt.Println("Password does not match")
        fmt.Println(user.Password, " ", credentials.Password)
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
        return
    }
    token := generateToken(user.ID)
    c.JSON(http.StatusOK, gin.H{"token": token})
}

func createTask(c *gin.Context) {
    var task Task
    if err := c.ShouldBindJSON(&task); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    result := db.Create(&task)
    if result.Error != nil {
        fmt.Println("Database Error:", result.Error) 
        c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
        return
    }
    c.JSON(http.StatusCreated, task)
}
func getTasks(c *gin.Context) {
    var tasks []Task
    result := db.Find(&tasks)
    if result.Error != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
        return
    }
    c.JSON(http.StatusOK, tasks)
}