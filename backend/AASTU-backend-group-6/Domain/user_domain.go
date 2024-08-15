package domain

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempity" json:"id" `
	Email    string             `json:"email"`
	Username string             `json:"username"`
	Password string             `json:"password"`
	Profile  string             `json:"profile"`
	GoogleID string             `json:"googleId"`
	Posts	[]Post           `json:"posts"`
	ResetToken string           `json:"resetToken"`
	Contact  string             `json:"contact"`	
	Bio	  string             `json:"bio"`		
	Role   string           `json:"roles"`
	
}