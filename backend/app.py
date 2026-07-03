from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import pandas as pd
import joblib

from features import extract_features
app = FastAPI()

templates = Jinja2Templates(directory="templates")
model = joblib.load("model.pkl")
label_encoder = joblib.load("label_encoder.pkl")
@app.post("/predict", response_class=HTMLResponse)
async def predict(request: Request, url: str = Form(...)):
    features = extract_features(url)

    features = pd.DataFrame([features])

    prediction = model.predict(features)

    result = label_encoder.inverse_transform(prediction)[0]

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "prediction": result,
            "url": url
        }
    )