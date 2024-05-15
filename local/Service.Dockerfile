FROM mcr.microsoft.com/dotnet/sdk:8.0-alpine3.18 AS build-env

RUN apk update && apk upgrade
RUN apk add --no-cache clang build-base zlib-dev libssl1.1

ARG PROJECT_NAME

WORKDIR /app

COPY . ./
RUN dotnet publish src/${PROJECT_NAME}/${PROJECT_NAME}.csproj -o /publish -c Release -r linux-musl-x64

FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine3.18
RUN apk update && apk upgrade
RUN apk add --no-cache libstdc++

WORKDIR /app
COPY --from=build-env /publish .