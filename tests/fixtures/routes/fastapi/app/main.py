from fastapi import Depends, FastAPI

from .routers import items
from .auth import get_current_user

app = FastAPI()
app.include_router(items.router, prefix='/api', dependencies=[Depends(get_current_user)])


@app.get('/ping')
async def ping():
    return {'ok': True}


@app.get('/me')
async def me(user=Depends(get_current_user)):
    return user


@app.delete('/sessions/{session_id}', dependencies=[Depends(verify_token)])
async def logout(session_id: str):
    return None
