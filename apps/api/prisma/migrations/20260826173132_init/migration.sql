-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "scanType" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "severity" TEXT NOT NULL,
    "findings" JSONB NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Alert" (
    "id" TEXT NOT NULL,
    "scanId" TEXT,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "blocked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Alert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Setting" (
    "key" TEXT NOT NULL,
    "value" JSONB NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Setting_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "WhitelistEntry" (
    "id" TEXT NOT NULL,
    "hostname" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WhitelistEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Scan_hostname_idx" ON "Scan"("hostname");

-- CreateIndex
CREATE INDEX "Scan_timestamp_idx" ON "Scan"("timestamp");

-- CreateIndex
CREATE INDEX "Scan_severity_idx" ON "Scan"("severity");

-- CreateIndex
CREATE INDEX "Alert_hostname_idx" ON "Alert"("hostname");

-- CreateIndex
CREATE INDEX "Alert_createdAt_idx" ON "Alert"("createdAt");

-- CreateIndex
CREATE INDEX "Alert_severity_idx" ON "Alert"("severity");

-- CreateIndex
CREATE UNIQUE INDEX "WhitelistEntry_hostname_key" ON "WhitelistEntry"("hostname");

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE SET NULL ON UPDATE CASCADE;
