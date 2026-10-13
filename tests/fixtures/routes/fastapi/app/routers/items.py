from fastapi import APIRouter, Query

router = APIRouter(prefix='/items')


@router.get('/{item_id}')
async def read_item(item_id: int, q: str = Query(None)):
    return {'item_id': item_id}


@router.post('/')
async def create_item(item: dict):
    return item
