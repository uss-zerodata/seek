"""`/api/v1/inventory` - the software inventory of the whole model.

The document is the JSON export's, built by the same function, so a client of
the API and a reader of an exported file get one shape. It reads the model, so
the route is a plain `def` and runs in the threadpool.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from seek.nmap import export as exporter
from seek.web import schemas as s
from seek.web.deps import session

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])


@router.get("", response_model=s.InventoryDocument, response_model_by_alias=True)
def get_inventory(sess=Depends(session)):
    return s.InventoryDocument.model_validate(exporter.inventory_document(
        exporter.records_for(sess.scans.hosts), sess.inventory()))
