"""FastAPI application main entry point"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import create_tables
from app.api.v1.router import router as v1_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for application startup and shutdown events.
    
    Args:
        app: FastAPI application instance
    """
    # Startup
    print("Creating database tables...")
    await create_tables()
    yield
    # Shutdown
    print("Application shutting down...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="A code security service for analyzing and monitoring code repositories",
    lifespan=lifespan,
)

# Include routers
app.include_router(v1_router)


@app.get("/", tags=["health"])
async def health_check() -> dict:
    """
    Health check endpoint.
    
    Returns:
        dict: Status and service information
    """
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
    )
