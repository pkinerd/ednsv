# syntax=docker/dockerfile:1.7
ARG DOTNET_VERSION=8.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

COPY src/Ednsv.Core/Ednsv.Core.csproj src/Ednsv.Core/
COPY src/Ednsv.Web/Ednsv.Web.csproj src/Ednsv.Web/
RUN dotnet restore src/Ednsv.Web/Ednsv.Web.csproj

COPY src/Ednsv.Core/ src/Ednsv.Core/
COPY src/Ednsv.Web/ src/Ednsv.Web/
RUN dotnet publish src/Ednsv.Web/Ednsv.Web.csproj \
        --configuration Release \
        --no-restore \
        --output /app/publish \
        /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_NOLOGO=1

EXPOSE 8080

COPY --from=build /app/publish ./

ENTRYPOINT ["dotnet", "Ednsv.Web.dll"]
