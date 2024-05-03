from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import boto3

from phone import phone_number

app = FastAPI()

USER_POOL_ID = 'ap-south-1_KeB73DJui'
CLIENT_ID = '26cp6t9mffbmjrbjcoudp86520'
client = boto3.client('cognito-idp', region_name='ap-south-1')


class User(BaseModel):
    username: str
    password: str


class VerifyOtpCommand(BaseModel):
    session: str
    code: str
    challenge_name: str
    username: str


# Signup endpoint
@app.post('/signup')
def signup(user: User):
    try:
        response = client.sign_up(
            ClientId=CLIENT_ID,
            Username=user.username,
            Password=user.password,
            UserAttributes=[
                {
                    'Name': 'phone_number',
                    'Value': phone_number
                },
            ]
        )
        return {'message': 'User signed up successfully'}
    except client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail='Username already exists')
    except client.exceptions.ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post('/login')
def login(user: User):
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',  # USER_PASSWORD_AUTH
            AuthParameters={
                'USERNAME': user.username,
                'PASSWORD': user.password
            }
        )
        auth_result = response.get("AuthenticationResult", None)
        challenge_name = response.get("ChallengeName", None)
        if auth_result:
            return {'access_token': response['AuthenticationResult']['AccessToken']}
        elif challenge_name == "SMS_MFA":
            return {'challenge_name': response.get("ChallengeName"), "session": response.get("Session")}
    except client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail='Incorrect username or password')
    except client.exceptions.UserNotFoundException:
        raise HTTPException(status_code=404, detail='User does not exist')
    except client.exceptions.ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post('/verify_otp')
def verify_otp(verify_otp: VerifyOtpCommand):
    try:
        response = client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName=verify_otp.challenge_name,
            Session=verify_otp.session,
            ChallengeResponses={"USERNAME": verify_otp.username,
                                "SMS_MFA_CODE": verify_otp.code})
        return {'access_token': response}
    except client.exceptions.ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post('/refresh_token')
def refresh_token(refresh_token: str):
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="REFRESH_TOKEN",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token
            })
        return response
    except client.exceptions.ClientError as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app, host='0.0.0.0', port=8000)
