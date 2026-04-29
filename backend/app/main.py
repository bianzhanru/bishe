from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.fuzz_api import router as fuzz_router

app = FastAPI(title="物联网状态敏感模糊测试系统", description="后端调度中枢")

# 允许前端跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "后端核心服务运行正常！"}

# 把刚才写的 API 接口注册到主程序里
app.include_router(fuzz_router, prefix="/api", tags=["Fuzzing"])
