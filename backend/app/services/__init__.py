"""Application services: transaction-scoped business operations over the models.

Services receive an :class:`~sqlalchemy.ext.asyncio.AsyncSession` from the
caller (API route, engine, or worker) and never commit — the caller owns the
transaction boundary.
"""
