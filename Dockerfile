# syntax=docker/dockerfile:1.7
ARG DOTNET_VERSION=10.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

# The commit this image was built from, stamped into AssemblyInformationalVersion and
# surfaced by the UI, /api/defaults and the startup log. The SDK would normally derive
# this from the git checkout, but only the sources are copied in — there is no .git
# here — so without this argument every image reports a bare version and no revision,
# and a running pod cannot be told apart from any other build.
ARG SOURCE_COMMIT=""
ARG SOURCE_BRANCH=""
ARG SOURCE_PR=""

# global.json comes first so the container honours the same SDK pin as CI and dev
# boxes rather than silently building on whatever band the base image happens to ship.
COPY global.json ./
COPY src/Ednsv.Core/Ednsv.Core.csproj src/Ednsv.Core/
COPY src/Ednsv.Web/Ednsv.Web.csproj src/Ednsv.Web/
RUN dotnet restore src/Ednsv.Web/Ednsv.Web.csproj

COPY src/Ednsv.Core/ src/Ednsv.Core/
COPY src/Ednsv.Web/ src/Ednsv.Web/
RUN dotnet publish src/Ednsv.Web/Ednsv.Web.csproj \
        --configuration Release \
        --no-restore \
        --output /app/publish \
        /p:UseAppHost=false \
        /p:SourceRevisionId="$SOURCE_COMMIT" \
        /p:SourceBranch="$SOURCE_BRANCH" \
        /p:SourcePullRequest="$SOURCE_PR"

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS runtime
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_NOLOGO=1

EXPOSE 8080

COPY --from=build /app/publish ./

ENTRYPOINT ["dotnet", "Ednsv.Web.dll"]
