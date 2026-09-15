from fastapi import FastAPI, HTTPException 
from pydantic import BaseModel 
import joblib 
import numpy as np 

app = FastAPI(    
    title="Binary Network Intrusion Detection",    
    description="Machine Learning Model deployed using FastAPI",    
    version="1.0.0" 
    )

# FILE_ID = "1hV1f-PX8lYDpYneNMwuuf64U0I2Ni8lV"
# MODEL_PATH = "model.pkl"

# # Download model only if it doesn't exist
# if not os.path.exists(MODEL_PATH):
#     print("Model not found. Downloading...")

#     gdown.download(
#         f"https://drive.google.com/uc?id={FILE_ID}",
#         MODEL_PATH,
#         quiet=False
#     )

# else:
#     print("Model already exists. Skipping download.")

# # Load model
# model = joblib.load(MODEL_PATH)

# print("Model loaded successfully!")

MODEL_PATH = "model.pkl" 
try:    
    model = joblib.load(MODEL_PATH)    
    print("Model loaded successfully") 
except Exception as e:    
    print("Error loading model:", e)    
    model = None

from pydantic import BaseModel


class ClassificationInput(BaseModel):
    Destination_Port: float
    Flow_Duration: float
    Total_Fwd_Packets: float
    Total_Backward_Packets: float
    Total_Length_of_Fwd_Packets: float
    Total_Length_of_Bwd_Packets: float
    Fwd_Packet_Length_Max: float
    Fwd_Packet_Length_Min: float
    Fwd_Packet_Length_Mean: float
    Fwd_Packet_Length_Std: float
    Bwd_Packet_Length_Max: float
    Bwd_Packet_Length_Min: float
    Bwd_Packet_Length_Mean: float
    Bwd_Packet_Length_Std: float
    Flow_Bytes_s: float
    Flow_Packets_s: float
    Flow_IAT_Mean: float
    Flow_IAT_Std: float
    Flow_IAT_Max: float
    Flow_IAT_Min: float
    Fwd_IAT_Total: float
    Fwd_IAT_Mean: float
    Fwd_IAT_Std: float
    Fwd_IAT_Max: float
    Fwd_IAT_Min: float
    Bwd_IAT_Total: float
    Bwd_IAT_Mean: float
    Bwd_IAT_Std: float
    Bwd_IAT_Max: float
    Bwd_IAT_Min: float
    Fwd_PSH_Flags: int
    Bwd_PSH_Flags: int
    Fwd_URG_Flags: int
    Bwd_URG_Flags: int
    Fwd_Header_Length: float
    Bwd_Header_Length: float
    Fwd_Packets_s: float
    Bwd_Packets_s: float
    Min_Packet_Length: float
    Max_Packet_Length: float
    Packet_Length_Mean: float
    Packet_Length_Std: float
    Packet_Length_Variance: float
    FIN_Flag_Count: int
    RST_Flag_Count: int
    PSH_Flag_Count: int
    ACK_Flag_Count: int
    URG_Flag_Count: int
    Down_Up_Ratio: float
    Average_Packet_Size: float
    Fwd_Avg_Bytes_Bulk: int
    Fwd_Avg_Packets_Bulk: int
    Fwd_Avg_Bulk_Rate: int
    Bwd_Avg_Bytes_Bulk: int
    Bwd_Avg_Packets_Bulk: int
    Bwd_Avg_Bulk_Rate: int
    Subflow_Bwd_Bytes: float
    Init_Win_bytes_forward: float
    Init_Win_bytes_backward: float
    act_data_pkt_fwd: float
    min_seg_size_forward: int
    Active_Mean: float
    Active_Std: float
    Active_Max: float
    Active_Min: float
    Idle_Mean: float
    Idle_Std: float
    Idle_Max: float
    Idle_Min: float
    Init_Win_bytes_backward_missing: int
    Init_Win_bytes_forward_missing: int

@app.get("/") 
def home():    
    return {        
        "message": "ML Model API is running",        
        "status": "success"    
    }

@app.get("/health") 
def health():    
    if model is None:        
        return {"status": "unhealthy", "model_loaded": False}    
    return {"status": "healthy", "model_loaded": True}

@app.post("/predict") 
def predict(data: ClassificationInput):    
    input_data = np.array([[        
        data.Destination_Port,
data.Flow_Duration,
data.Total_Fwd_Packets,
data.Total_Backward_Packets,
data.Total_Length_of_Fwd_Packets,
data.Total_Length_of_Bwd_Packets,
data.Fwd_Packet_Length_Max,
data.Fwd_Packet_Length_Min,
data.Fwd_Packet_Length_Mean,
data.Fwd_Packet_Length_Std,
data.Bwd_Packet_Length_Max,
data.Bwd_Packet_Length_Min,
data.Bwd_Packet_Length_Mean,
data.Bwd_Packet_Length_Std,
data.Flow_Bytes_s,
data.Flow_Packets_s,
data.Flow_IAT_Mean,
data.Flow_IAT_Std,
data.Flow_IAT_Max,
data.Flow_IAT_Min,
data.Fwd_IAT_Total,
data.Fwd_IAT_Mean,
data.Fwd_IAT_Std,
data.Fwd_IAT_Max,
data.Fwd_IAT_Min,
data.Bwd_IAT_Total,
data.Bwd_IAT_Mean,
data.Bwd_IAT_Std,
data.Bwd_IAT_Max,
data.Bwd_IAT_Min,
data.Fwd_PSH_Flags,
data.Bwd_PSH_Flags,
data.Fwd_URG_Flags,
data.Bwd_URG_Flags,
data.Fwd_Header_Length,
data.Bwd_Header_Length,
data.Fwd_Packets_s,
data.Bwd_Packets_s,
data.Min_Packet_Length,
data.Max_Packet_Length,
data.Packet_Length_Mean,
data.Packet_Length_Std,
data.Packet_Length_Variance,
data.FIN_Flag_Count,
data.RST_Flag_Count,
data.PSH_Flag_Count,
data.ACK_Flag_Count,
data.URG_Flag_Count,
data.Down_Up_Ratio,
data.Average_Packet_Size,
data.Fwd_Avg_Bytes_Bulk,
data.Fwd_Avg_Packets_Bulk,
data.Fwd_Avg_Bulk_Rate,
data.Bwd_Avg_Bytes_Bulk,
data.Bwd_Avg_Packets_Bulk,
data.Bwd_Avg_Bulk_Rate,
data.Subflow_Bwd_Bytes,
data.Init_Win_bytes_forward,
data.Init_Win_bytes_backward,
data.act_data_pkt_fwd,
data.min_seg_size_forward,
data.Active_Mean,
data.Active_Std,
data.Active_Max,
data.Active_Min,
data.Idle_Mean,
data.Idle_Std,
data.Idle_Max,
data.Idle_Min,
data.Init_Win_bytes_backward_missing,
data.Init_Win_bytes_forward_missing    
    ]])    
    prediction = model.predict(input_data)[0]    
    probabilities = model.predict_proba(input_data)[0]    
    max_probability = max(probabilities)    
    return {        
        "prediction": str(prediction),        
        "probability": round(float(max_probability), 4)   
    }
