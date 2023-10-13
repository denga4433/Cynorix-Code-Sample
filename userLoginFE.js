import React, { useRef, useState } from "react";
import { ErrorMessage, Field, Formik } from "formik";
import { Button, Col, Form, Row } from "react-bootstrap";
import { toAbsoluteUrl } from "../../../_metronic/_helpers";
import "../../../_metronic/_assets/sass/pages/login/login-2.scss";
import * as yup from "yup";
import { Link, withRouter } from "react-router-dom";
import { fireAuth } from "../../utils/firebase";
import { sendPasswordResetEmail, signInWithEmailAndPassword } from "@firebase/auth";
import { toast } from "react-hot-toast";

/**
 * The Login component
 * @param {*} props {}
 * @returns {JSX.Element} The Login component
 */
function Login(props) {
  const [serverError, setServerError] = useState("");
  // Login page has two "states": whether the user is resetting their password, or the default. forgotPassword determines which form to display.
  const [forgotPassword, setForgotPassword] = useState("none");
  // rememberPassword is simply the "opposite" of forgotPassword, used for convenience in JSX component props.
  const [rememberPassword, setRememberPassword] = useState("inline");
  // Used to refer the email from the login page over to the forgot password page.
  const ref = useRef(null);

  // Logging in is exclusively done with Firebase's API, no backend validation/POSTs are necessary.
  // The only states that need to be retrieved can be done in private/logged-in user only pages before mounting.
  const handleSubmit = async (values, { setSubmitting }) => {
    try {
      setSubmitting(true);
      await signInWithEmailAndPassword(fireAuth, values.email, values.password);
      toast.success("Successfully logged in!");
      props.history.replace("/dashboard");
    } catch (error) {
      console.log(error);
      toast.error("Invalid credentials");
      setSubmitting(false);
      setServerError("Invalid credentials");
    }
  };

  const handleForgotSubmit = async (e) => {
    try {
      await sendPasswordResetEmail(fireAuth, ref.current.values.email, { url: `${process.env.REACT_APP_PUBLIC_URL}` });
      toast.success("Please check your email for a password reset link.");
    } catch (error) {
      toast.error("Invalid email");
    }
  };

  const schema = yup.object({
    email: yup.string().required("Please enter an email"),
    password: yup.string().required("Please enter a password")
  });

  const forgotSchema = yup.object({
    email: yup.string().email().required("Please enter a valid email")
  });

  const toggleForgotPassword = () => {
    if (forgotPassword === "inline") {
      setForgotPassword("none");
      setRememberPassword("inline");
    } else {
      setForgotPassword("inline");
      setRememberPassword("none");
    }
  };

  return (
    <div className="d-flex flex-column flex-root">
      {/*begin::Login*/}
      <div
        className="login login-2 d-flex flex-column flex-lg-row flex-column-fluid bg-white login-signin-on"
        id="kt_login"
      >
        {/*begin::Aside*/}
        <div className="login-aside order-2 order-lg-1 d-flex flex-row-auto position-relative overflow-hidden">
          {/*--begin: Aside Container*/}
          <div className="d-flex flex-column-fluid flex-column justify-content-between py-9 px-7 py-lg-13 px-lg-35">
            {/*--begin::Logo*/}
            <a href="/login" className="text-center pt-2">
              <img alt="" className="max-h-70px" src={toAbsoluteUrl("/media/logos/logo-1.png")} />
            </a>
            {/*--end::Logo*/}

            {/*--begin::Aside body*/}
            <div className="d-flex flex-column-fluid flex-column flex-center">
              {/*--begin::Signin*/}
              <div className="login-form login-signin py-11" style={{ display: rememberPassword }}>
                {/*--begin::Form*/}
                <Formik
                  enableReinitialize
                  initialValues={{
                    email: "",
                    password: ""
                  }}
                  validationSchema={schema}
                  onSubmit={handleSubmit}
                >
                  {({ handleSubmit, isSubmitting, handleChange }) => (
                    <Form onSubmit={handleSubmit}>
                      <Form.Row>
                        <Form.Label className="font-weight-bolder text-dark font-size-h2 font-size-h1-lg">
                          Sign In
                          <br></br>
                        </Form.Label>
                      </Form.Row>
                      <Form.Row>
                        <Form.Label className="font-weight-bolder text-dark font-size-h7 font-size-h7-lg">
                          <h4>
                            Don't have an account? Create a{" "}
                            <Link to="/registration">user account</Link> or an{" "}
                            <Link to="/orgRegistration">organization account</Link>
                          </h4>
                        </Form.Label>
                      </Form.Row>
                      <Form.Row>
                        <Form.Group as={Col}>
                          <Row>
                            <Col>
                              <Form.Label className="font-size-h6 font-weight-bolder text-dark pl-0">
                                Email
                              </Form.Label>
                            </Col>
                          </Row>
                          <Row>
                            <Col>
                              <Field
                                autoComplete="off"
                                disabled={isSubmitting}
                                type="text"
                                name="email"
                                id="email"
                                className="form-control"
                                onChange={(e) => {
                                  handleChange(e);
                                  setServerError("");
                                }}
                              />
                            </Col>
                          </Row>
                          <Row>
                            <Col>
                              <ErrorMessage name="email" component="div" />
                            </Col>
                          </Row>
                        </Form.Group>
                      </Form.Row>
                      <Form.Row>
                        <Form.Group as={Col}>
                          <Row>
                            <Col>
                              <Form.Label className="font-size-h6 font-weight-bolder text-dark">
                                Password
                              </Form.Label>
                            </Col>
                          </Row>
                          <Row>
                            <Col>
                              <Field
                                autoComplete="off"
                                disabled={isSubmitting}
                                type="password"
                                name="password"
                                id="password"
                                className="form-control"
                                onChange={(e) => {
                                  handleChange(e);
                                  setServerError("");
                                }}
                              />
                            </Col>
                          </Row>
                          <Row>
                            <Col>
                              <ErrorMessage name="password" component="div" />
                            </Col>
                          </Row>
                        </Form.Group>
                      </Form.Row>
                      <Row>
                        <Col>
                          <Button variant="primary" type="submit" disabled={isSubmitting}>
                            Submit
                          </Button>
                          {serverError ? <div>{serverError}</div> : undefined}
                        </Col>
                      </Row>
                    </Form>
                  )}
                </Formik>
                <button className="btn btn-link border-0 p-0 mt-4" onClick={toggleForgotPassword}>Forgotten password?
                </button>
                {/*--end::Form*/}
              </div>
              {/*--end::Signin*/}

              {/*--begin::Forgot*/}
              <div className="pt-11" style={{ display: forgotPassword }}>
                {/*--begin::Form*/}
                <Formik
                  enableReinitialize
                  validationSchema={forgotSchema}
                  initialValues={{ email: "" }}
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleForgotSubmit(e);
                  }}
                  innerRef={ref}>
                  {({ isSubmitting, handleChange }) => (
                    <form
                      className="form fv-plugins-bootstrap fv-plugins-framework"
                      noValidate="noValidate"
                      id="kt_login_forgot_form"
                      onSubmit={(e) => {
                        e.preventDefault();
                        handleForgotSubmit(e);
                      }}
                    >
                      {/*--begin::Title*/}
                      <div className="">
                        <h2 className="font-weight-bolder text-dark font-size-h2 font-size-h1-lg">
                          Forgotten password?
                        </h2>
                        <p className="text-muted font-weight-bold font-size-h4 my-2">
                          Enter your email to reset your password
                        </p>
                      </div>
                      {/*--end::Title*/}
                      <Form.Row>
                        <Form.Group as={Col}>
                          <Row>
                            <Col>
                              <Field
                                autoComplete="off"
                                disabled={isSubmitting}
                                type="text"
                                name="email"
                                id="email"
                                className="form-control form-control-solid h-auto py-6 px-6 rounded-lg font-size-h6 my-5"
                                placeholder="Email"
                                onChange={(e) => {
                                  handleChange(e);
                                  setServerError("");
                                }}
                              />
                            </Col>
                          </Row>
                          <Row>
                            <Col>
                              <ErrorMessage className="text-danger" name="email" component="div" />
                            </Col>
                          </Row>
                        </Form.Group>
                      </Form.Row>
                      {/*--end::Form group*/}
                      {/*--begin::Form group*/}
                      <div className="form-group d-flex flex-wrap pb-lg-0 pb-3">
                        <button
                          type="submit"
                          id="kt_login_forgot_submit"
                          className="btn btn-primary font-weight-bolder font-size-h6 px-8 py-4 my-3 mr-4"
                          onClick={(e) => {
                            e.preventDefault();
                            handleForgotSubmit(e);
                          }}
                          variant="primary"
                          disabled={isSubmitting}
                        >
                          Submit
                        </button>
                        <button
                          type="button"
                          id="kt_login_forgot_cancel"
                          className="btn btn-light-primary font-weight-bolder font-size-h6 px-8 py-4 my-3 mx-4"
                          onClick={toggleForgotPassword}
                        >
                          Cancel
                        </button>
                      </div>
                      {/*--end::Form group*/}
                    </form>
                  )}
                </Formik>
                {/*--end::Form*/}
              </div>
              {/*--end::Forgot*/}
            </div>
            {/*--end::Aside body*/}
          </div>
        </div>
        {/*begin::Aside*/}

        <div className="content order-1 order-lg-2 d-flex flex-column w-100 pb-0">
          <div
            className="d-flex flex-column justify-content-center text-center pt-lg-40 pt-md-5 pt-sm-5 px-lg-0 pt-5 px-7">
            <h3 className="display4 font-weight-bolder my-7 text-dark" style={{ color: "#986923" }}>
              Cynorix Secure Authentication
            </h3>
            <p className="font-weight-bolder font-size-h2-md font-size-lg text-dark opacity-70">
              Cynorix Two-Factor Authentication
              <br />
              An Intelligent &amp; Secure Two-Factor Authentication
            </p>
          </div>

          <div
            className="d-flex flex-row-fluid bgi-no-repeat bgi-position-y-top bgi-position-x-center w-100"
            style={{
              backgroundImage: `url(${toAbsoluteUrl(
                "/media/cynorix/multi.jpg"
              )})`
            }}
          ></div>
        </div>
      </div>

      {/*end::Login*/}
    </div>
  );
}

export default withRouter(Login);