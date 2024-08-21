package gemini_ai

import (
	"context"
	"fmt"
	"time"

	"github.com/RealEskalate/-g5-project-phase-starter-project/astu/backend/g4/chat"
	"github.com/google/generative-ai-go/genai"
)


type AIService struct{
	model *genai.GenerativeModel
	BlogPrompt  string
	TitlePrompt string
}


func NewAIService(model *genai.GenerativeModel, blogPrompt, titlePrompt string) *AIService{
	return &AIService{
		model: model,
		BlogPrompt: blogPrompt,
		TitlePrompt: titlePrompt,
	}
}



func (aiService *AIService) SendMessage(ctx context.Context, history []chat.Message, message chat.Message) (chat.Message, error){
	var chatSessionHistory []*genai.Content
	for _, message := range history{
		content := genai.Content{
			Parts: []genai.Part{
				genai.Text(message.Text),
			},

			Role: message.Role,
		}

		chatSessionHistory = append(chatSessionHistory, &content)
	}


	chatSession := aiService.model.StartChat()
	chatSession.History = chatSessionHistory

	if chatSession.History == nil{
		content := genai.Content{
			Parts: []genai.Part{
				genai.Text(aiService.BlogPrompt),
			},

			Role: "user",
		}

		chatSessionHistory = append(chatSessionHistory, &content)
	}


	response, err := chatSession.SendMessage(ctx, genai.Text(message.Text))
	if err != nil{
		return chat.Message{}, err
	}

	candidate := response.Candidates[0]
	return chat.Message{
		Text: fmt.Sprintf("%s", candidate.Content.Parts[0]),
		Role: candidate.Content.Role,
		SentAt: time.Now(),
	}, nil
}


func (aiService *AIService) GenerateChatTitle(ctx context.Context, text string) (string, error){
	response, err := aiService.model.GenerateContent(ctx, genai.Text(aiService.TitlePrompt + text))
	if err != nil{
		return "", err
	}

	return fmt.Sprintf("%s", response.Candidates[0].Content.Parts[0]), nil
}




